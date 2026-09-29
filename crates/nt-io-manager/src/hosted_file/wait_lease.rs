//! Exact leases for broker-owned FILE_OBJECT wait projections.
//!
//! The native adapter serializes this ledger with its projection-row catalog. A wait lease pins
//! the exact row and hosted File binding through rendezvous; it does not replace the canonical
//! File reference or the publication lease owned by the broker.

use super::HostedFileIdentity;
use alloc::vec::Vec;
use nt_status::NtStatus;

#[derive(Clone, Copy, Debug)]
struct WaitLease {
    token: u64,
    row_id: u64,
    identity: HostedFileIdentity,
}

/// Monotonic, exact-token lease ledger for native FILE_OBJECT wait rows.
#[derive(Debug, Default)]
pub struct HostedFileWaitLeaseLedger {
    next_token: u64,
    leases: Vec<WaitLease>,
}

impl HostedFileWaitLeaseLedger {
    pub const fn new() -> Self {
        Self {
            next_token: 0,
            leases: Vec::new(),
        }
    }

    /// Acquire an independent lease, including when another wait already holds this same row.
    /// A still-leased row cannot be rebound to another hosted File generation.
    pub fn acquire(
        &mut self,
        row_id: u64,
        identity: HostedFileIdentity,
    ) -> Result<u64, NtStatus> {
        if row_id == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if self
            .leases
            .iter()
            .any(|lease| lease.row_id == row_id && lease.identity != identity)
        {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        let token = self
            .next_token
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        self.leases
            .try_reserve(1)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        self.leases.push(WaitLease {
            token,
            row_id,
            identity,
        });
        self.next_token = token;
        Ok(token)
    }

    /// Release only the exact token, row, and hosted File binding. A refused release changes
    /// nothing, so its caller retains the receipt for diagnosis or redrive.
    pub fn release(
        &mut self,
        token: u64,
        row_id: u64,
        identity: HostedFileIdentity,
    ) -> Result<(), NtStatus> {
        let index = self
            .leases
            .iter()
            .position(|lease| {
                token != 0
                    && lease.token == token
                    && lease.row_id == row_id
                    && lease.identity == identity
            })
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        self.leases.swap_remove(index);
        Ok(())
    }

    pub fn has_lease(&self, row_id: u64, identity: HostedFileIdentity) -> bool {
        self.leases
            .iter()
            .any(|lease| lease.row_id == row_id && lease.identity == identity)
    }

    /// Native row retirement is permitted only after every wait using that row has resolved.
    pub fn can_retire(&self, row_id: u64) -> bool {
        row_id != 0 && !self.leases.iter().any(|lease| lease.row_id == row_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileId, HostedDomainId, HostedDomainIdentity};

    fn identity(address: u64, generation: u64) -> HostedFileIdentity {
        HostedFileIdentity {
            manager: 1,
            domain: HostedDomainIdentity {
                domain_id: HostedDomainId::new(1, 1),
                cookie: 2,
            },
            file: FileId::new(1, 1),
            address,
            sequence: generation,
        }
    }

    #[test]
    fn multiple_waits_pin_one_exact_row_until_the_last_release() {
        let mut ledger = HostedFileWaitLeaseLedger::new();
        let file = identity(0x1000, 1);
        let first = ledger.acquire(10, file).unwrap();
        let second = ledger.acquire(10, file).unwrap();
        assert_ne!(first, second);
        assert!(ledger.has_lease(10, file));
        assert!(!ledger.can_retire(10));
        ledger.release(first, 10, file).unwrap();
        assert!(ledger.has_lease(10, file));
        assert!(!ledger.can_retire(10));
        ledger.release(second, 10, file).unwrap();
        assert!(!ledger.has_lease(10, file));
        assert!(ledger.can_retire(10));
    }

    #[test]
    fn rejects_stale_duplicate_and_mismatched_release_without_losing_owner() {
        let mut ledger = HostedFileWaitLeaseLedger::new();
        let file = identity(0x1000, 1);
        let token = ledger.acquire(10, file).unwrap();
        for (candidate, row, binding) in [
            (0, 10, file),
            (token + 1, 10, file),
            (token, 11, file),
            (token, 10, identity(0x1000, 2)),
            (token, 10, identity(0x2000, 1)),
        ] {
            assert_eq!(
                ledger.release(candidate, row, binding),
                Err(NtStatus::INVALID_PARAMETER)
            );
            assert!(ledger.has_lease(10, file));
        }
        ledger.release(token, 10, file).unwrap();
        assert_eq!(ledger.release(token, 10, file), Err(NtStatus::INVALID_PARAMETER));
    }

    #[test]
    fn row_reuse_cannot_obscure_a_live_generation_or_resurrect_an_old_token() {
        let mut ledger = HostedFileWaitLeaseLedger::new();
        let old = identity(0x1000, 1);
        let new = identity(0x1000, 2);
        let old_token = ledger.acquire(10, old).unwrap();
        assert_eq!(ledger.acquire(10, new), Err(NtStatus::OBJECT_NAME_COLLISION));
        assert!(!ledger.has_lease(10, new));
        ledger.release(old_token, 10, old).unwrap();
        let new_token = ledger.acquire(10, new).unwrap();
        assert_ne!(old_token, new_token);
        assert_eq!(ledger.release(old_token, 10, old), Err(NtStatus::INVALID_PARAMETER));
        assert!(ledger.has_lease(10, new));
        ledger.release(new_token, 10, new).unwrap();
    }

    #[test]
    fn zero_row_and_token_exhaustion_do_not_publish_leases() {
        let mut ledger = HostedFileWaitLeaseLedger::new();
        let file = identity(0x1000, 1);
        assert_eq!(ledger.acquire(0, file), Err(NtStatus::INVALID_PARAMETER));
        assert!(!ledger.can_retire(0));
        ledger.next_token = u64::MAX;
        assert_eq!(ledger.acquire(10, file), Err(NtStatus::INSUFFICIENT_RESOURCES));
        assert!(!ledger.has_lease(10, file));
        assert!(ledger.can_retire(10));
    }
}
