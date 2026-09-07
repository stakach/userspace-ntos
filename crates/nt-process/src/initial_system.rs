//! Explicit bootstrap identity, independent of process names, fixed CIDs or token subjects.
use crate::{
    ProcessId, ProcessManager, ProcessState, ThreadId, ThreadLifetime, ThreadState,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
};
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_DESIGNATION: AtomicU64 = AtomicU64::new(1);

/// Identity metadata for this ProcessManager's designated initial System process and thread.
/// This copy does not own their references. A unique designation nonce rejects releases against
/// another ProcessManager even when its independent PID/TID namespace happens to match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialSystemIdentity {
    thread: ThreadLifetime,
    designation: u64,
}

impl InitialSystemIdentity {
    pub const fn process_id(self) -> ProcessId {
        self.thread.process_id()
    }

    pub const fn thread_id(self) -> ThreadId {
        self.thread.thread_id()
    }

    pub const fn thread(self) -> ThreadLifetime {
        self.thread
    }
}

pub(crate) struct InitialSystemRoot {
    identity: InitialSystemIdentity,
    references_held: bool,
}

impl ProcessManager {
    /// Designate normally allocated bootstrap objects and acquire one kernel reference to each.
    /// Object bodies, scheduler mechanisms and primary-token ownership are separate publications.
    /// All checks precede mutation; designation allocates nothing and can succeed only once.
    pub fn designate_initial_system(
        &mut self,
        pid: ProcessId,
        tid: ThreadId,
    ) -> Result<InitialSystemIdentity, u32> {
        self.designate_initial_system_with_counter(pid, tid, &NEXT_DESIGNATION)
    }

    fn designate_initial_system_with_counter(
        &mut self,
        pid: ProcessId,
        tid: ThreadId,
        counter: &AtomicU64,
    ) -> Result<InitialSystemIdentity, u32> {
        if self.initial_system.is_some() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        let thread = self.thread(tid).ok_or(STATUS_INVALID_HANDLE)?;
        if process.state != ProcessState::Running
            || process.main_thread != Some(tid)
            || thread.process_id != pid
            || !thread.is_system_thread
            || matches!(
                thread.state,
                ThreadState::Initialized | ThreadState::Terminated
            )
            || process.exit_status.is_some()
            || thread.exit_status.is_some()
            || process.peb_base_address != 0
            || thread.teb_base != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let process_references = process
            .kernel_pointer_references
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let thread_references = thread
            .kernel_pointer_references
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let designation = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                if value == 0 {
                    None
                } else {
                    value.checked_add(1)
                }
            })
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let identity = InitialSystemIdentity {
            thread: self
                .thread_lifetime(tid)
                .expect("validated bootstrap thread"),
            designation,
        };
        self.processes
            .get_mut(&pid)
            .unwrap()
            .kernel_pointer_references = process_references;
        self.threads
            .get_mut(&tid)
            .unwrap()
            .kernel_pointer_references = thread_references;
        self.initial_system = Some(InitialSystemRoot {
            identity,
            references_held: true,
        });
        Ok(identity)
    }

    /// Return the designated identity only while its exact objects still exist. Termination does
    /// not delete object identity; normal references retain it until the delete procedure runs.
    pub fn initial_system_identity(&self) -> Option<InitialSystemIdentity> {
        let identity = self.initial_system.as_ref()?.identity;
        (self.process(identity.process_id()).is_some()
            && self.validate_thread_lifetime(identity.thread))
        .then_some(identity)
    }

    /// Fence retained-reference cleanup even after the designated objects have been deleted.
    /// This does not admit new work or prove that the initial System objects remain live.
    pub(crate) fn has_initial_system_designation(&self, identity: InitialSystemIdentity) -> bool {
        self.initial_system
            .as_ref()
            .is_some_and(|root| root.identity == identity)
    }

    pub fn is_initial_system_process(&self, pid: ProcessId) -> bool {
        self.initial_system_identity()
            .is_some_and(|identity| identity.process_id() == pid)
    }

    /// Validate explicit kernel-originated work against this manager's live bootstrap identity.
    /// This is structural caller admission, not token authorization: consumers must still resolve
    /// the canonical current primary and thread impersonation, without assuming System privileges.
    /// A parked thread may retain work, but terminated or uninitialized identities cannot admit it.
    pub fn validate_initial_system_caller(&self, identity: InitialSystemIdentity) -> bool {
        self.initial_system_identity() == Some(identity)
            && self.initial_system_references_held()
            && self.process(identity.process_id()).is_some_and(|process| {
                process.state == ProcessState::Running && process.exit_status.is_none()
            })
            && self.thread(identity.thread_id()).is_some_and(|thread| {
                thread.is_system_thread
                    && thread.exit_status.is_none()
                    && !matches!(
                        thread.state,
                        ThreadState::Initialized | ThreadState::Terminated
                    )
            })
    }

    pub fn initial_system_references_held(&self) -> bool {
        self.initial_system
            .as_ref()
            .is_some_and(|root| root.references_held)
    }

    /// Explicitly release the bootstrap owner's two references, once, during bootstrap rollback or
    /// final system teardown. Other Ps/Ob references remain intact. The one-time designation is
    /// not reset, and no object is implicitly terminated or deleted by releasing these references.
    pub fn release_initial_system_references(
        &mut self,
        identity: InitialSystemIdentity,
    ) -> Result<(), u32> {
        let root = self
            .initial_system
            .as_ref()
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if !root.references_held
            || root.identity != identity
            || self.initial_system_identity() != Some(identity)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let pid = identity.process_id();
        let tid = identity.thread_id();
        let process_references = self
            .process(pid)
            .unwrap()
            .kernel_pointer_references
            .checked_sub(1)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let thread_references = self
            .thread(tid)
            .unwrap()
            .kernel_pointer_references
            .checked_sub(1)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        self.processes
            .get_mut(&pid)
            .unwrap()
            .kernel_pointer_references = process_references;
        self.threads
            .get_mut(&tid)
            .unwrap()
            .kernel_pointer_references = thread_references;
        self.initial_system.as_mut().unwrap().references_held = false;
        Ok(())
    }

    pub(crate) fn initial_system_process_reference_floor(&self, pid: ProcessId) -> u32 {
        u32::from(
            self.initial_system
                .as_ref()
                .is_some_and(|root| root.references_held && root.identity.process_id() == pid),
        )
    }

    pub(crate) fn initial_system_thread_reference_floor(&self, tid: ThreadId) -> u32 {
        u32::from(
            self.initial_system
                .as_ref()
                .is_some_and(|root| root.references_held && root.identity.thread_id() == tid),
        )
    }
}

#[cfg(test)]
#[path = "initial_system_tests.rs"]
mod tests;
