//! Multiple exact queued callbacks from one provider.
//!
//! A callback's queue claim and physical worker remain separate authorities. A parked
//! worker cannot be reused for another entry, including through a different route
//! whose TCB or request bank aliases it. The native adapter authenticates both keys
//! before invoking any callback or acknowledging a terminal.

use alloc::vec::Vec;

use crate::{HostedWorkQueueClaim, HostedWorkQueueClaimError};

/// The native adapter supplies its own physical identity and alias check. Exact
/// equality includes route, dispatch, Reply and generation; `aliases_execution`
/// rejects reuse of any still-owned execution lane or request bank.
pub trait HostedWorkQueueWorker: Copy + Eq {
    fn aliases_execution(self, other: Self) -> bool;
}

// A compact witness used by the host contracts: route, dispatch, Reply, TCB, bank.
// Native identities implement this trait with their typed route and generation.
impl HostedWorkQueueWorker for (u64, u64, u64, u64, u64) {
    fn aliases_execution(self, other: Self) -> bool {
        self.0 == other.0 || self.3 == other.3 || self.4 == other.4
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedWorkQueueClaimsError {
    DuplicateQueueKey,
    WorkerInUse,
    NoClaim,
    WrongWorker,
    AllocationFailed,
    InvalidPhase,
}

struct Row<K, P, E> {
    worker: P,
    claim: HostedWorkQueueClaim<K, E>,
}

/// Each row has its own physical worker. Claim order does not establish a parent
/// relation or require callbacks on independent workers to finish in LIFO order.
#[must_use = "retain every entered callback until its exact terminal ACK"]
pub struct HostedWorkQueueClaims<K, P, E> {
    rows: Vec<Row<K, P, E>>,
}

impl<K: Copy + Eq, P: HostedWorkQueueWorker, E: Copy> HostedWorkQueueClaims<K, P, E> {
    pub const fn new() -> Self { Self { rows: Vec::new() } }

    pub fn claim(
        &mut self, key: K, worker: P, entry: E,
    ) -> Result<(), HostedWorkQueueClaimsError> {
        if self.rows.iter().any(|row| row.claim.invocation() == key) {
            return Err(HostedWorkQueueClaimsError::DuplicateQueueKey);
        }
        if self.rows.iter().any(|row| worker.aliases_execution(row.worker)) {
            return Err(HostedWorkQueueClaimsError::WorkerInUse);
        }
        self.rows.try_reserve(1)
            .map_err(|_| HostedWorkQueueClaimsError::AllocationFailed)?;
        self.rows.push(Row { worker, claim: HostedWorkQueueClaim::dequeue(key, entry) });
        Ok(())
    }

    fn find_mut(
        &mut self, key: K, worker: P,
    ) -> Result<&mut Row<K, P, E>, HostedWorkQueueClaimsError> {
        let row = self.rows.iter_mut().find(|row| row.claim.invocation() == key)
            .ok_or(HostedWorkQueueClaimsError::NoClaim)?;
        if row.worker != worker { return Err(HostedWorkQueueClaimsError::WrongWorker); }
        Ok(row)
    }

    fn find(
        &self, key: K, worker: P,
    ) -> Result<&Row<K, P, E>, HostedWorkQueueClaimsError> {
        let row = self.rows.iter().find(|row| row.claim.invocation() == key)
            .ok_or(HostedWorkQueueClaimsError::NoClaim)?;
        if row.worker != worker { return Err(HostedWorkQueueClaimsError::WrongWorker); }
        Ok(row)
    }

    pub fn retained_entry(
        &self, key: K, worker: P,
    ) -> Result<&E, HostedWorkQueueClaimsError> {
        self.find(key, worker)?.claim.retained_entry(key)
            .map_err(Self::claim_error)
    }

    pub fn enter(
        &mut self, key: K, worker: P,
    ) -> Result<E, HostedWorkQueueClaimsError> {
        self.find_mut(key, worker)?.claim.enter(key).map_err(Self::claim_error)
    }

    pub fn entered(
        &self, key: K, worker: P,
    ) -> Result<bool, HostedWorkQueueClaimsError> {
        Ok(self.find(key, worker)?.claim.entered())
    }

    pub fn acknowledge_return(
        &mut self, key: K, worker: P,
    ) -> Result<(), HostedWorkQueueClaimsError> {
        let row = self.find_mut(key, worker)?;
        row.claim.acknowledge_return(key).map_err(Self::claim_error)?;
        let index = self.rows.iter().position(|row| row.claim.invocation() == key)
            .ok_or(HostedWorkQueueClaimsError::NoClaim)?;
        self.rows.swap_remove(index);
        Ok(())
    }

    pub fn abort_before_enter(
        &mut self, key: K, worker: P,
    ) -> Result<(), HostedWorkQueueClaimsError> {
        let row = self.find_mut(key, worker)?;
        row.claim.abort_before_enter(key).map_err(Self::claim_error)?;
        let index = self.rows.iter().position(|row| row.claim.invocation() == key)
            .ok_or(HostedWorkQueueClaimsError::NoClaim)?;
        self.rows.swap_remove(index);
        Ok(())
    }

    fn claim_error(error: HostedWorkQueueClaimError) -> HostedWorkQueueClaimsError {
        match error {
            HostedWorkQueueClaimError::WrongInvocation => HostedWorkQueueClaimsError::WrongWorker,
            HostedWorkQueueClaimError::NoClaim => HostedWorkQueueClaimsError::InvalidPhase,
        }
    }
}

impl<K: Copy + Eq, P: HostedWorkQueueWorker, E: Copy> Default
    for HostedWorkQueueClaims<K, P, E>
{
    fn default() -> Self { Self::new() }
}
