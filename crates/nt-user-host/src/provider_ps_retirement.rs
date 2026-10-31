//! Exact Ps target retained while a root-owned win32k exit callout runs.

use nt_process::{ProcessManager, ThreadLifetime, ThreadState, STATUS_INVALID_HANDLE};
use nt_types::ProcessIdentity;

/// The terminated GUI thread is the callout target, never the provider wait caller.
/// Both Ps pointers stay referenced through a parked callout and its completion ACK.
#[must_use = "retain the Ps target until the provider completion is acknowledged"]
pub struct PsRetirementTarget {
    process: ProcessIdentity,
    process_sequence: u64,
    thread: ThreadLifetime,
    eprocess: u64,
    ethread: u64,
    thread_released: bool,
    process_released: bool,
}

impl PsRetirementTarget {
    /// Capture the exact already terminated target. The adapter must authenticate the
    /// current hosted process generation before supplying `process`.
    pub fn capture(
        pm: &mut ProcessManager,
        process: ProcessIdentity,
        thread: ThreadLifetime,
        eprocess: u64,
        ethread: u64,
    ) -> Result<Self, u32> {
        if !process.is_valid()
            || process.pid != thread.process_id()
            || eprocess == 0
            || ethread == 0
            || eprocess == ethread
            || !pm.validate_thread_lifetime(thread)
            || pm.thread(thread.thread_id()).is_none_or(|row| row.state != ThreadState::Terminated)
            || pm.process_kernel_object(process.pid) != Some(eprocess)
            || pm.thread_kernel_object(thread.thread_id()) != Some(ethread)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let process_sequence = pm.process_sequence_for_kernel_process_object(eprocess)?;
        let (held_process, _) = pm.lookup_kernel_process_by_id(process.pid)?;
        if held_process != eprocess {
            pm.release_kernel_object_pointer(held_process)?;
            return Err(STATUS_INVALID_HANDLE);
        }
        let (held_thread, _) = match pm.lookup_kernel_thread_by_id(thread.thread_id()) {
            Ok(held) => held,
            Err(status) => {
                // This is a local Ps reference; its undo has no uncertain native effect.
                pm.release_kernel_object_pointer(eprocess)
                    .expect("captured process reference disappeared");
                return Err(status);
            }
        };
        if held_thread != ethread {
            pm.release_kernel_object_pointer(held_thread)?;
            pm.release_kernel_object_pointer(eprocess)?;
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(Self {
            process,
            process_sequence,
            thread,
            eprocess,
            ethread,
            thread_released: false,
            process_released: false,
        })
    }

    pub fn validate(&self, pm: &ProcessManager, current: ProcessIdentity) -> Result<(), u32> {
        if self.thread_released
            || self.process_released
            || current != self.process
            || !pm.validate_thread_lifetime(self.thread)
            || pm.process_kernel_object(self.process.pid) != Some(self.eprocess)
            || pm.thread_kernel_object(self.thread.thread_id()) != Some(self.ethread)
            || pm.process_sequence_for_kernel_process_object(self.eprocess)? != self.process_sequence
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    pub fn process(&self) -> ProcessIdentity { self.process }
    pub fn thread(&self) -> ThreadLifetime { self.thread }
    pub fn eprocess(&self) -> u64 { self.eprocess }
    pub fn ethread(&self) -> u64 { self.ethread }

    /// Release each reference once. A failed second release retains its remaining owner.
    pub fn release(&mut self, pm: &mut ProcessManager) -> Result<(), u32> {
        if self.process_released { return Err(STATUS_INVALID_HANDLE); }
        if !self.thread_released {
            pm.release_kernel_object_pointer(self.ethread)?;
            self.thread_released = true;
        }
        pm.release_kernel_object_pointer(self.eprocess)?;
        self.process_released = true;
        Ok(())
    }
}
