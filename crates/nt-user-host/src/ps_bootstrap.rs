//! Bootstrap Ps/Se ownership moved intact into the executive's long-lived handler.
use nt_process::{ProcessManager, ThreadState, STATUS_INVALID_PARAMETER};
use nt_security::{AccessToken, AnonymousLogonTokenIds, TokenStore};

/// Owns the original policy managers before native hosted-process admission. This is deliberately
/// not Clone: identities, captured token references and seeded children must survive one transfer,
/// not be reconstructed in a second set of managers. No native body or mechanism is created here.
pub struct PsBootstrapState {
    pm: ProcessManager,
    token_store: TokenStore,
    anonymous_logon_tokens: AnonymousLogonTokenIds,
}

/// Consuming handoff of the original managers and their security-subsystem token references.
pub struct PsBootstrapParts {
    pub pm: ProcessManager,
    pub token_store: TokenStore,
    pub anonymous_logon_tokens: AnonymousLogonTokenIds,
}

impl PsBootstrapState {
    /// Construct a real initial System process and running system thread through ordinary Ps
    /// allocation. Checked policy failures leave no published aggregate. The underlying process
    /// and token constructors retain their existing infallible allocation behavior.
    pub fn try_new(start_address: u64, parameter: u64) -> Result<Self, u32> {
        if start_address == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut pm = ProcessManager::new();
        let mut token_store = TokenStore::new();
        let pid = pm.create_process("System", None, None);
        let primary = token_store.insert(AccessToken::system());
        // TokenStore::insert's original reference becomes the process-owned primary reference.
        let replaced = pm.replace_process_primary_token(pid, Some(primary))?;
        debug_assert!(replaced.is_none());
        let tid = pm.create_thread(pid, start_address, parameter, true)?;
        pm.set_thread_state(tid, ThreadState::Running)?;
        pm.designate_initial_system(pid, tid)?;
        let anonymous_logon_tokens = token_store.insert_anonymous_logon_tokens();
        Ok(Self {
            pm,
            token_store,
            anonymous_logon_tokens,
        })
    }

    /// Seed real child objects in these same managers before the executive takes ownership.
    pub fn managers_mut(&mut self) -> (&mut ProcessManager, &mut TokenStore) {
        (&mut self.pm, &mut self.token_store)
    }

    pub fn process_manager(&self) -> &ProcessManager {
        &self.pm
    }

    pub fn token_store(&self) -> &TokenStore {
        &self.token_store
    }

    pub fn into_parts(self) -> PsBootstrapParts {
        PsBootstrapParts {
            pm: self.pm,
            token_store: self.token_store,
            anonymous_logon_tokens: self.anonymous_logon_tokens,
        }
    }
}

#[cfg(test)]
#[path = "ps_bootstrap_tests.rs"]
mod tests;
