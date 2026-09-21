//! Physical source attribution policy; identities are not capability or execution authority.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_IDENTITY: AtomicU64 = AtomicU64::new(1);

/// Native adapters retain exact catalog identity in Domain and authenticate physical records.
pub trait IngressSource: Copy + Eq {
    type Domain: Copy + Eq;
    type Kind: Copy + Eq;
    fn domain(self) -> Self::Domain;
    fn kind(self) -> Self::Kind;
    fn tcb(self) -> u64;
    fn vspace(self) -> u64;
    fn is_valid(self) -> bool;
}

/// Globally fresh attribution survives source-slot, CPtr and registry-object reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressSourceIdentity {
    domain: u64,
    generation: u64,
    source: u64,
}

impl IngressSourceIdentity {
    pub const fn domain(self) -> u64 {
        self.domain
    }
    pub const fn generation(self) -> u64 {
        self.generation
    }
    pub const fn source(self) -> u64 {
        self.source
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceError {
    InvalidSource,
    InvalidIdentity,
    NotLive,
    Conflict,
    Retired,
    InvalidPhase,
    NotDrained,
    NoCapacity,
    IdentityExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourcePhase {
    Active,
    Retiring,
    Retired,
}

struct DomainRecord<D> {
    physical: D,
    pml4: u64,
    id: u64,
    generation: u64,
}

struct SourceRecord<S> {
    identity: IngressSourceIdentity,
    physical: S,
    phase: SourcePhase,
}

pub struct IngressSourceRegistry<S: IngressSource> {
    domains: Vec<DomainRecord<S::Domain>>,
    sources: Vec<SourceRecord<S>>,
}

fn fresh_identity() -> Result<u64, SourceError> {
    NEXT_IDENTITY
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            if next == 0 {
                None
            } else {
                next.checked_add(1)
            }
        })
        .map_err(|_| SourceError::IdentityExhausted)
}

impl<S: IngressSource> IngressSourceRegistry<S> {
    pub const fn new() -> Self {
        Self {
            domains: Vec::new(),
            sources: Vec::new(),
        }
    }

    /// The verifier must check the owning catalog's exact generation and physical worker's
    /// TCB/VSpace/kind against retained source records. It must be observational/nonreentrant;
    /// matching numeric cptrs alone is not authentication. Allocation precedes publication.
    pub fn intern(
        &mut self,
        physical: S,
        verify: impl FnOnce(S) -> bool,
    ) -> Result<IngressSourceIdentity, SourceError> {
        if !physical.is_valid() {
            return Err(SourceError::InvalidSource);
        }
        if !verify(physical) {
            return Err(SourceError::NotLive);
        }
        if let Some(record) = self.sources.iter().find(|row| row.physical == physical) {
            return match record.phase {
                SourcePhase::Active => Ok(record.identity),
                SourcePhase::Retiring | SourcePhase::Retired => Err(SourceError::Retired),
            };
        }
        if self.sources.iter().any(|row| {
            row.phase != SourcePhase::Retired
                && (row.physical.tcb() == physical.tcb()
                    || (row.physical.domain() == physical.domain()
                        && row.physical.kind() == physical.kind()))
        }) {
            return Err(SourceError::Conflict);
        }
        let domain = self
            .domains
            .iter()
            .position(|row| row.physical == physical.domain());
        if domain.is_some_and(|index| self.domains[index].pml4 != physical.vspace()) {
            return Err(SourceError::Conflict);
        }
        self.sources
            .try_reserve(1)
            .map_err(|_| SourceError::NoCapacity)?;
        if domain.is_none() {
            self.domains
                .try_reserve(1)
                .map_err(|_| SourceError::NoCapacity)?;
        }
        let source = fresh_identity()?;
        let (domain_id, generation) = match domain {
            Some(index) => (self.domains[index].id, self.domains[index].generation),
            None => {
                let id = fresh_identity()?;
                let generation = fresh_identity()?;
                self.domains.push(DomainRecord {
                    physical: physical.domain(),
                    pml4: physical.vspace(),
                    id,
                    generation,
                });
                (id, generation)
            }
        };
        let identity = IngressSourceIdentity {
            domain: domain_id,
            generation,
            source,
        };
        self.sources.push(SourceRecord {
            identity,
            physical,
            phase: SourcePhase::Active,
        });
        Ok(identity)
    }

    fn index(&self, identity: IngressSourceIdentity) -> Result<usize, SourceError> {
        self.sources
            .iter()
            .position(|row| row.identity == identity)
            .ok_or(SourceError::InvalidIdentity)
    }

    fn resolve_phase(
        &self,
        identity: IngressSourceIdentity,
        phase: SourcePhase,
        verify: impl FnOnce(S) -> bool,
    ) -> Result<S, SourceError> {
        let row = &self.sources[self.index(identity)?];
        if row.phase != phase {
            return Err(SourceError::InvalidPhase);
        }
        if !verify(row.physical) {
            return Err(SourceError::NotLive);
        }
        Ok(row.physical)
    }

    pub fn resolve(
        &self,
        identity: IngressSourceIdentity,
        verify: impl FnOnce(S) -> bool,
    ) -> Result<S, SourceError> {
        self.resolve_phase(identity, SourcePhase::Active, verify)
    }

    /// Authenticate a queued sender only for cancellation/drain, never execution admission.
    pub fn resolve_retiring(
        &self,
        identity: IngressSourceIdentity,
        verify: impl FnOnce(S) -> bool,
    ) -> Result<S, SourceError> {
        self.resolve_phase(identity, SourcePhase::Retiring, verify)
    }

    pub fn begin_retirement(
        &mut self,
        identity: IngressSourceIdentity,
        verify: impl FnOnce(S) -> bool,
    ) -> Result<(), SourceError> {
        self.resolve(identity, verify)?;
        let index = self.index(identity)?;
        self.sources[index].phase = SourcePhase::Retiring;
        Ok(())
    }

    /// The coordinator must prove matching PeerInstallation retirement, native sender/alias
    /// quiescence and complete Call/continuation drain. This records a tombstone only: no capability
    /// effects, source-catalog removal, slot recycling or sibling-domain retirement occur here.
    pub fn finish_retirement(
        &mut self,
        identity: IngressSourceIdentity,
        prove_drained: impl FnOnce(S) -> bool,
    ) -> Result<(), SourceError> {
        let index = self.index(identity)?;
        let row = &self.sources[index];
        if row.phase != SourcePhase::Retiring {
            return Err(SourceError::InvalidPhase);
        }
        if !prove_drained(row.physical) {
            return Err(SourceError::NotDrained);
        }
        self.sources[index].phase = SourcePhase::Retired;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
