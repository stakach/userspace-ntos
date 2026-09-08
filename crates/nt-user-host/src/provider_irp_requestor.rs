//! A provider IRP retains its actual logical requestor thread independently of its executor lane.

use nt_process::{InitialSystemIdentity, ProcessManager, ThreadLifetime};
use nt_process::native_handle::{NativeObjectReference, PsHandleType};
use nt_types::AccessMode;

use crate::provider_logical_caller::{ProviderCallerError, ProviderLogicalCaller};
use crate::thread_binding::ThreadBinding;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderIrpRequestorError {
    Caller(ProviderCallerError),
    InvalidInitialSystem,
    Process(u32),
}

/// One exact Ps thread reference, not a process pointer or the provider's physical executor TCB.
/// The native IRP arena separately authenticates its provider, lane and dispatch ownership.
/// Keep this owner until IRP completion/abort and requestor-list unlink, including pending I/O.
/// Dropping it cannot contact the PM; explicit release is required and errors retain ownership.
///
/// ```compile_fail
/// use nt_user_host::provider_irp_requestor::ProviderIrpRequestor;
/// fn duplicate(owner: ProviderIrpRequestor) { let _ = owner.clone(); }
/// ```
#[must_use = "retain the requestor until IRP retirement and explicitly release its Ps reference"]
pub struct ProviderIrpRequestor {
    lifetime: ThreadLifetime,
    reference: NativeObjectReference,
}

impl ProviderIrpRequestor {
    /// `admitted` must come from fresh authenticated ingress in the same canonical PM, never
    /// provider-supplied metadata or a pending runtime row. All checks precede reference capture.
    pub fn capture_hosted<R>(
        caller: ProviderLogicalCaller,
        admitted: Option<ThreadBinding<R>>,
        pm: &mut ProcessManager,
    ) -> Result<Self, ProviderIrpRequestorError> {
        caller
            .validate(admitted, pm.thread_lifetime(caller.thread().thread_id()))
            .map_err(ProviderIrpRequestorError::Caller)?;
        Self::capture(caller.thread(), pm)
    }

    /// The native channel must explicitly carry this root-issued System designation. Absence
    /// of a hosted caller does not authorize this branch.
    pub fn capture_initial_system(
        identity: InitialSystemIdentity,
        pm: &mut ProcessManager,
    ) -> Result<Self, ProviderIrpRequestorError> {
        if !pm.validate_initial_system_caller(identity) {
            return Err(ProviderIrpRequestorError::InvalidInitialSystem);
        }
        Self::capture(identity.thread(), pm)
    }

    fn capture(
        lifetime: ThreadLifetime,
        pm: &mut ProcessManager,
    ) -> Result<Self, ProviderIrpRequestorError> {
        let caller = pm
            .capture_native_handle_caller(lifetime, AccessMode::KernelMode)
            .map_err(ProviderIrpRequestorError::Process)?;
        let reference = pm
            .reference_native_ps_handle(caller, u64::MAX - 1, Some(PsHandleType::Thread), 0)
            .map_err(ProviderIrpRequestorError::Process)?;
        Ok(Self { lifetime, reference })
    }

    pub const fn thread_lifetime(&self) -> ThreadLifetime {
        self.lifetime
    }

    pub const fn requestor_tid(&self) -> u64 {
        self.lifetime.thread_id() as u64
    }

    /// A body is available only while this owner holds its reference. Copying the address does
    /// not transfer that reference to the provider or authorize a later request from another job.
    pub const fn thread_body(&self) -> Option<u64> {
        if self.reference.is_held() {
            Some(self.reference.body())
        } else {
            None
        }
    }

    pub const fn is_held(&self) -> bool {
        self.reference.is_held()
    }

    /// Retirement checks the original PM and thread incarnation, not current runtime liveness.
    /// A thread which exited while I/O was pending must still be releasable exactly once.
    pub fn release(&mut self, pm: &mut ProcessManager) -> Result<(), ProviderIrpRequestorError> {
        self.reference
            .release(pm)
            .map_err(ProviderIrpRequestorError::Process)
    }
}

#[cfg(test)]
#[path = "provider_irp_requestor_tests.rs"]
mod tests;
