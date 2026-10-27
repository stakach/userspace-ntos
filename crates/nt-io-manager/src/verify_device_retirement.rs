//! Exact binding from a live ETHREAD activation to its `DeviceToVerify` projection.
//!
//! The native owner reserves capacity before writing the ETHREAD field and commits
//! the row only after that write succeeds. Retirement clears the field while the
//! matching physical registration is still retained, then removes its exact row.

use alloc::vec::Vec;
use nt_status::NtStatus;

use crate::HostedDevicePointerRegistration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadVerifyIdentity {
    pub body: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Binding {
    thread: ThreadVerifyIdentity,
    registration: HostedDevicePointerRegistration,
}

#[derive(Default)]
pub struct VerifyDeviceBindings {
    rows: Vec<Binding>,
}

impl VerifyDeviceBindings {
    pub const fn new() -> Self { Self { rows: Vec::new() } }

    pub fn reserve_write(
        &mut self,
        thread: ThreadVerifyIdentity,
        registration: Option<HostedDevicePointerRegistration>,
    ) -> Result<(), NtStatus> {
        if thread.body == 0 || thread.generation == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if registration.is_some() && !self.rows.iter().any(|row| row.thread == thread) {
            self.rows.try_reserve(1).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        }
        Ok(())
    }

    /// Infallible after `reserve_write`, with no intervening ledger mutation.
    pub fn commit_write(
        &mut self,
        thread: ThreadVerifyIdentity,
        registration: Option<HostedDevicePointerRegistration>,
    ) {
        self.rows.retain(|row| row.thread.thread_id != thread.thread_id);
        if let Some(registration) = registration {
            self.rows.push(Binding { thread, registration });
        }
    }

    pub fn next_for_retirement(
        &self,
        registration: HostedDevicePointerRegistration,
    ) -> Option<ThreadVerifyIdentity> {
        self.rows.iter().find(|row| row.registration == registration).map(|row| row.thread)
    }

    pub fn forget_exact(
        &mut self,
        thread: ThreadVerifyIdentity,
        registration: HostedDevicePointerRegistration,
    ) -> bool {
        let Some(index) = self.rows.iter().position(|row| {
            row.thread == thread && row.registration == registration
        }) else { return false; };
        self.rows.swap_remove(index);
        true
    }

    pub fn forget_thread(&mut self, thread: ThreadVerifyIdentity) {
        self.rows.retain(|row| row.thread != thread);
    }
}
