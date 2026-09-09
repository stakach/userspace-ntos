//! Prepare virtual registry roots before the executive publishes its registry namespace.

use alloc::vec::Vec;
use nt_process::ProcessManager;
use nt_security::{
    assign_registry_root_security, CapturedSubjectContext, SecurityAssignmentAudit,
    SubjectClientIdentity, TokenStore,
};

const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;
const STATUS_NO_TOKEN: u32 = 0xc000_007c;
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;

pub struct RegistryRootSecurity {
    pub machine: Vec<u8>,
    pub user: Vec<u8>,
}

/// Capture the designated initial System caller from the original PM/TokenStore, never from a
/// PID/name/SID guess or a newly synthesized token. Both descriptors and token-reference cleanup
/// complete before publication. The caller must treat failure as failed namespace initialization.
pub fn prepare_registry_root_security(
    pm: &ProcessManager,
    tokens: &mut TokenStore,
) -> Result<RegistryRootSecurity, u32> {
    let identity = pm.initial_system_identity().ok_or(STATUS_INVALID_HANDLE)?;
    if !pm.validate_initial_system_caller(identity) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let primary = pm
        .process_primary_token(identity.process_id())
        .ok_or(STATUS_NO_TOKEN)?;
    let client = pm
        .thread_impersonation(identity.thread_id())
        .map(|context| SubjectClientIdentity {
            token: context.token,
            level: context.level,
        });
    let mut capture =
        CapturedSubjectContext::capture(tokens, primary, client, u64::from(identity.process_id()))?;
    let result = (|| {
        let subject = capture.resolve(tokens)?;
        let mut audit = SecurityAssignmentAudit::default();
        let machine = assign_registry_root_security(&subject, &mut audit)?;
        // Root policy supplies neither an explicit owner nor SACL. Do not silently discard an
        // audit obligation if that policy changes before a bootstrap audit sink is available.
        if audit != SecurityAssignmentAudit::default() {
            return Err(STATUS_NOT_SUPPORTED);
        }
        let mut user = Vec::new();
        user.try_reserve_exact(machine.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        user.extend_from_slice(&machine);
        Ok(RegistryRootSecurity { machine, user })
    })();
    capture.release(tokens)?;
    result
}

#[cfg(test)]
#[path = "registry_bootstrap_tests.rs"]
mod tests;
