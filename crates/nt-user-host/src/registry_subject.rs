//! Security-subject ownership for an admitted native registry operation.

use nt_process::{native_handle::NativeHandleCaller, ProcessManager};
use nt_security::{
    CapturedSubjectContext, CapturedSubjectTokens, ProcessorMode, SubjectClientIdentity, TokenStore,
};
use nt_types::AccessMode;

/// Owns captured token references across CM IPC, descriptor admission and handle publication.
/// A captured subject is not permission to publish: publication must independently revalidate
/// the retained caller and target. Explicit release uses the original canonical TokenStore.
#[must_use = "registry subjects must explicitly release their captured token references"]
#[derive(Debug)]
pub struct RegistrySubject {
    caller: NativeHandleCaller,
    subject: CapturedSubjectContext,
}

impl RegistrySubject {
    /// Native adapters authenticate the runtime before constructing `caller`. These must be the
    /// executive's paired original PM and TokenStore, never reconstructed stores with matching IDs.
    pub fn capture(
        pm: &ProcessManager,
        tokens: &mut TokenStore,
        caller: NativeHandleCaller,
    ) -> Result<Self, u32> {
        pm.validate_native_handle_caller(caller)?;
        // Security follows the original actor, not a handle-table attachment. PM currently admits
        // only unattached callers; keeping the distinction here avoids changing subject policy
        // when effective-process attachment is introduced.
        let actor = caller.original_thread();
        let primary = pm
            .process_primary_token(actor.process_id())
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let client =
            pm.thread_impersonation(actor.thread_id())
                .map(|context| SubjectClientIdentity {
                    token: context.token,
                    level: context.level,
                });
        let subject = CapturedSubjectContext::capture(
            tokens,
            primary,
            client,
            u64::from(actor.process_id()),
        )?;
        Ok(Self { caller, subject })
    }

    pub const fn caller(&self) -> NativeHandleCaller {
        self.caller
    }

    pub const fn mode(&self) -> ProcessorMode {
        match self.caller.mode() {
            AccessMode::UserMode => ProcessorMode::UserMode,
            AccessMode::KernelMode => ProcessorMode::KernelMode,
        }
    }

    /// Resolves the captured identities even after process/thread token reassignment. This does
    /// not re-read live tokens or silently switch security principals after an IPC boundary.
    pub fn resolve<'a>(&'a self, tokens: &'a TokenStore) -> Result<CapturedSubjectTokens<'a>, u32> {
        self.subject.resolve(tokens)
    }

    pub fn release(&mut self, tokens: &mut TokenStore) -> Result<(), u32> {
        self.subject.release(tokens)
    }
}

#[cfg(test)]
#[path = "registry_subject_tests.rs"]
mod tests;
