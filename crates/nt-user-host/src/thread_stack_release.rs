//! Captured NT5 user-stack release policy, distinct from VAD or backing ownership.
use crate::process_identity::ProcessIdentity;
use nt_process::ThreadLifetime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadStackExitKind {
    RegisteredThread,
    FailedConstruction,
}

/// The caller authenticates the target TEB and supplies a checked reader in that process.
/// This captures the NT5 FreeStackOnTermination request, not permission to infer a VAD from
/// INITIAL_TEB bounds. A requested base (including zero) still needs ordinary MEM_RELEASE
/// validation. Keep this evidence across a failed release; Drop never frees memory.
///
/// ```compile_fail
/// use nt_user_host::thread_stack_release::ThreadStackReleaseRequest;
/// fn duplicate(value: &ThreadStackReleaseRequest) -> ThreadStackReleaseRequest { value.clone() }
/// ```
#[derive(Debug)]
#[must_use = "retain captured stack-release policy until the request is handled"]
pub struct ThreadStackReleaseRequest {
    process: ProcessIdentity,
    thread: ThreadLifetime,
    teb: u64,
    deallocation_stack: u64,
}

impl ThreadStackReleaseRequest {
    /// Failed creation never takes ownership of its caller's stack. An absent TEB likewise has
    /// no opt-in policy. Read exceptions are returned unchanged, never converted into a false flag.
    pub fn capture(
        process: ProcessIdentity,
        thread: ThreadLifetime,
        teb: Option<u64>,
        kind: ThreadStackExitKind,
        mut read: impl FnMut(u64, &mut [u8]) -> Result<(), u32>,
    ) -> Result<Option<Self>, u32> {
        if kind == ThreadStackExitKind::FailedConstruction || teb.is_none() {
            return Ok(None);
        }
        if !process.is_valid() || thread.process_id() != process.pid {
            return Err(nt_address_space::STATUS_INVALID_PARAMETER);
        }
        let teb = teb.expect("present TEB checked above");
        let address = |offset: usize, len: usize| {
            if teb == 0 {
                return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
            }
            let address = teb
                .checked_add(offset as u64)
                .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?;
            address
                .checked_add(len as u64)
                .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?;
            Ok(address)
        };
        let mut flag = [0u8; 1];
        read(
            address(
                core::mem::offset_of!(nt_ntdll_layout::Teb, free_stack_on_termination),
                1,
            )?,
            &mut flag,
        )?;
        if flag[0] == 0 {
            return Ok(None);
        }
        let mut base = [0u8; 8];
        read(
            address(
                core::mem::offset_of!(nt_ntdll_layout::Teb, deallocation_stack),
                8,
            )?,
            &mut base,
        )?;
        Ok(Some(Self {
            process,
            thread,
            teb,
            deallocation_stack: u64::from_le_bytes(base),
        }))
    }

    pub fn matches(&self, process: ProcessIdentity, thread: ThreadLifetime, teb: u64) -> bool {
        self.process == process && self.thread == thread && self.teb == teb
    }

    pub fn deallocation_stack(&self) -> u64 {
        self.deallocation_stack
    }
    pub fn teb(&self) -> u64 {
        self.teb
    }

    pub(crate) fn matches_thread(&self, process: ProcessIdentity, thread: ThreadLifetime) -> bool {
        self.process == process && self.thread == thread
    }
}

#[cfg(test)]
#[path = "thread_stack_release_tests.rs"]
mod tests;
