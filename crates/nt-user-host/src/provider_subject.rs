//! Provider-owned captured subjects with exact, explicit publication and reference retirement.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_process::{
    InitialSystemIdentity, ProcessId, ProcessManager, ProcessState, ThreadId, ThreadState,
};
use nt_provider_wait::{CatalogIdentity, ProviderDomainCatalog, ProviderDomainIdentity};
use nt_security::{
    CapturedSubjectContext, CapturedSubjectTokens, SubjectClientIdentity, TokenStore,
};

use crate::provider_logical_caller::{ProviderCallerError, ProviderLogicalCaller};
use crate::thread_binding::ThreadBinding;

static NEXT_LEASE: AtomicU64 = AtomicU64::new(1);

/// A real broker lease identity, not a native SECURITY_SUBJECT_CONTEXT field or token pointer.
/// Values never repeat across registry instances. Numeric reconstruction does not grant ownership:
/// every request still checks provider identity, catalog liveness and the owning registry row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderSubjectLeaseId(u64);

impl ProviderSubjectLeaseId {
    pub const fn from_raw(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderSubjectError {
    InvalidProvider,
    StaleProvider,
    InvalidCaller,
    Caller(ProviderCallerError),
    NoToken,
    InvalidLease,
    OwnerMismatch,
    CatalogMismatch,
    WrongPhase,
    Capacity,
    IdentityExhausted,
    Security(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prepared,
    Published,
}

struct Entry {
    id: ProviderSubjectLeaseId,
    provider: ProviderDomainIdentity,
    catalog: CatalogIdentity,
    phase: Phase,
    subject: CapturedSubjectContext,
}

/// Non-cloneable owner of every prepared and published token-reference pair. Dropping a registry
/// does not release references from an external store: explicit abort, release or provider drain
/// is required before the owner is discarded. Provider-request methods require the same canonical
/// domain catalog used at capture, not a separately constructed catalog with colliding identities.
#[must_use = "captured subjects must be explicitly released against their original token store"]
pub struct ProviderSubjectRegistry {
    entries: Vec<Entry>,
    limit: usize,
}

impl ProviderSubjectRegistry {
    pub const fn new() -> Self {
        Self::with_limit(usize::MAX)
    }

    /// Bound outstanding leases independently of Vec allocation capacity.
    pub const fn with_limit(limit: usize) -> Self {
        Self {
            entries: Vec::new(),
            limit,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn count_for_provider(
        &self,
        provider: ProviderDomainIdentity,
        catalog: CatalogIdentity,
    ) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.provider == provider && entry.catalog == catalog)
            .count()
    }

    /// `admitted` must be the freshly authenticated executable runtime, never an ownership-only
    /// pending row. The retained caller's generation is checked against the canonical PM here.
    /// The PM and TokenStore must be the executive's original paired managers, not reconstructed
    /// stores or provider-supplied objects whose numeric token IDs merely happen to match.
    pub fn prepare_hosted<R>(
        &mut self,
        provider: ProviderDomainIdentity,
        catalog: &ProviderDomainCatalog,
        caller: ProviderLogicalCaller,
        admitted: Option<ThreadBinding<R>>,
        pm: &ProcessManager,
        tokens: &mut TokenStore,
    ) -> Result<ProviderSubjectLeaseId, ProviderSubjectError> {
        let catalog = validate_provider(provider, catalog)?;
        let tid = caller.thread().thread_id();
        caller
            .validate(admitted, pm.thread_lifetime(tid))
            .map_err(ProviderSubjectError::Caller)?;
        self.prepare(
            provider,
            catalog,
            caller.process().pid,
            tid,
            pm,
            tokens,
            &NEXT_LEASE,
        )
    }

    /// Initial System is an explicit, exact designation from this PM, never absence of a hosted
    /// caller. Its current thread impersonation is captured just like any other thread's.
    pub fn prepare_initial_system(
        &mut self,
        provider: ProviderDomainIdentity,
        catalog: &ProviderDomainCatalog,
        identity: InitialSystemIdentity,
        pm: &ProcessManager,
        tokens: &mut TokenStore,
    ) -> Result<ProviderSubjectLeaseId, ProviderSubjectError> {
        let catalog = validate_provider(provider, catalog)?;
        if pm.initial_system_identity() != Some(identity)
            || !pm.initial_system_references_held()
            || !pm
                .thread(identity.thread_id())
                .is_some_and(|thread| thread.is_system_thread)
        {
            return Err(ProviderSubjectError::InvalidCaller);
        }
        self.prepare(
            provider,
            catalog,
            identity.process_id(),
            identity.thread_id(),
            pm,
            tokens,
            &NEXT_LEASE,
        )
    }

    fn prepare(
        &mut self,
        provider: ProviderDomainIdentity,
        catalog: CatalogIdentity,
        pid: ProcessId,
        tid: ThreadId,
        pm: &ProcessManager,
        tokens: &mut TokenStore,
        counter: &AtomicU64,
    ) -> Result<ProviderSubjectLeaseId, ProviderSubjectError> {
        let process = pm.process(pid).ok_or(ProviderSubjectError::InvalidCaller)?;
        let thread = pm.thread(tid).ok_or(ProviderSubjectError::InvalidCaller)?;
        if thread.process_id != pid
            || process.state == ProcessState::Terminated
            || matches!(
                thread.state,
                ThreadState::Initialized | ThreadState::Terminated
            )
        {
            return Err(ProviderSubjectError::InvalidCaller);
        }
        let primary = pm
            .process_primary_token(pid)
            .ok_or(ProviderSubjectError::NoToken)?;
        let client = pm
            .thread_impersonation(tid)
            .map(|context| SubjectClientIdentity {
                token: context.token,
                level: context.level,
            });
        if self.entries.len() >= self.limit {
            return Err(ProviderSubjectError::Capacity);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| ProviderSubjectError::Capacity)?;
        let id = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                if value == 0 {
                    None
                } else {
                    value.checked_add(1)
                }
            })
            .map(ProviderSubjectLeaseId)
            .map_err(|_| ProviderSubjectError::IdentityExhausted)?;
        let subject = CapturedSubjectContext::capture(tokens, primary, client, u64::from(pid))
            .map_err(ProviderSubjectError::Security)?;
        // All fallible storage/identity preparation precedes capture. No callbacks or external
        // publication run while TokenStore is mutably borrowed.
        self.entries.push(Entry {
            id,
            provider,
            catalog,
            phase: Phase::Prepared,
            subject,
        });
        Ok(id)
    }

    /// Publish an already-owned lease after native output preparation succeeds. Failure leaves the
    /// Prepared row and references intact for abort or trusted provider rundown.
    pub fn publish(
        &mut self,
        provider: ProviderDomainIdentity,
        catalog: &ProviderDomainCatalog,
        id: ProviderSubjectLeaseId,
    ) -> Result<(), ProviderSubjectError> {
        let catalog = validate_provider(provider, catalog)?;
        let index = self.index(provider, catalog, id)?;
        if self.entries[index].phase != Phase::Prepared {
            return Err(ProviderSubjectError::WrongPhase);
        }
        self.entries[index].phase = Phase::Published;
        Ok(())
    }

    pub fn resolve<'a>(
        &'a self,
        provider: ProviderDomainIdentity,
        catalog: &ProviderDomainCatalog,
        id: ProviderSubjectLeaseId,
        tokens: &'a TokenStore,
    ) -> Result<CapturedSubjectTokens<'a>, ProviderSubjectError> {
        let catalog = validate_provider(provider, catalog)?;
        let entry = &self.entries[self.index(provider, catalog, id)?];
        if entry.phase != Phase::Published {
            return Err(ProviderSubjectError::WrongPhase);
        }
        entry
            .subject
            .resolve(tokens)
            .map_err(ProviderSubjectError::Security)
    }

    pub fn abort_prepared(
        &mut self,
        provider: ProviderDomainIdentity,
        catalog: &ProviderDomainCatalog,
        id: ProviderSubjectLeaseId,
        tokens: &mut TokenStore,
    ) -> Result<(), ProviderSubjectError> {
        self.release_phase(provider, catalog, id, tokens, Phase::Prepared)
    }

    pub fn release(
        &mut self,
        provider: ProviderDomainIdentity,
        catalog: &ProviderDomainCatalog,
        id: ProviderSubjectLeaseId,
        tokens: &mut TokenStore,
    ) -> Result<(), ProviderSubjectError> {
        self.release_phase(provider, catalog, id, tokens, Phase::Published)
    }

    fn release_phase(
        &mut self,
        provider: ProviderDomainIdentity,
        catalog: &ProviderDomainCatalog,
        id: ProviderSubjectLeaseId,
        tokens: &mut TokenStore,
        phase: Phase,
    ) -> Result<(), ProviderSubjectError> {
        let catalog = validate_provider(provider, catalog)?;
        let index = self.index(provider, catalog, id)?;
        if self.entries[index].phase != phase {
            return Err(ProviderSubjectError::WrongPhase);
        }
        self.release_index(index, tokens)
    }

    /// Trusted executive rundown, not a provider-request route. The exact owner's generation may
    /// already be retired in the domain catalog. Both prepared and published rows are drained;
    /// failed release retains that row and all remaining owners for retry, without allocation.
    pub fn drain_provider(
        &mut self,
        provider: ProviderDomainIdentity,
        catalog: CatalogIdentity,
        tokens: &mut TokenStore,
    ) -> Result<usize, ProviderSubjectError> {
        if !provider.is_valid() {
            return Err(ProviderSubjectError::InvalidProvider);
        }
        let mut released = 0;
        let mut index = 0;
        while index < self.entries.len() {
            if self.entries[index].provider == provider && self.entries[index].catalog == catalog {
                self.release_index(index, tokens)?;
                released += 1;
            } else {
                index += 1;
            }
        }
        Ok(released)
    }

    fn index(
        &self,
        provider: ProviderDomainIdentity,
        catalog: CatalogIdentity,
        id: ProviderSubjectLeaseId,
    ) -> Result<usize, ProviderSubjectError> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(ProviderSubjectError::InvalidLease)?;
        if self.entries[index].provider != provider {
            return Err(ProviderSubjectError::OwnerMismatch);
        }
        if self.entries[index].catalog != catalog {
            return Err(ProviderSubjectError::CatalogMismatch);
        }
        Ok(index)
    }

    fn release_index(
        &mut self,
        index: usize,
        tokens: &mut TokenStore,
    ) -> Result<(), ProviderSubjectError> {
        self.entries[index]
            .subject
            .release(tokens)
            .map_err(ProviderSubjectError::Security)?;
        self.entries.swap_remove(index);
        Ok(())
    }
}

impl Default for ProviderSubjectRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_provider(
    provider: ProviderDomainIdentity,
    catalog: &ProviderDomainCatalog,
) -> Result<CatalogIdentity, ProviderSubjectError> {
    if !provider.is_valid() {
        Err(ProviderSubjectError::InvalidProvider)
    } else if !catalog.contains(provider) {
        Err(ProviderSubjectError::StaleProvider)
    } else {
        catalog
            .identity()
            .ok_or(ProviderSubjectError::StaleProvider)
    }
}

#[cfg(test)]
#[path = "provider_subject_tests.rs"]
mod tests;
