use alloc::string::String;
use alloc::vec::Vec;

use nt_hive_core::CellId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SystemKeyLease {
    pub(crate) token: u64,
    pub(crate) key: CellId,
    pub(crate) physical_path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemKeyLeaseError {
    Exhausted,
    Invalid,
}

/// Growable CM-owned identities for native handles into the mounted SYSTEM hive.
///
/// A lease stores the stable hive cell rather than a caller path. This preserves an open key's
/// physical identity if `Select\Current` later changes. Whole-hive replacement invalidates every
/// lease because cell identities belong to the replaced mount generation.
pub(crate) struct SystemKeyLeaseBank {
    leases: Vec<Option<SystemKeyLease>>,
    next_token: u64,
}

impl SystemKeyLeaseBank {
    pub(crate) const fn new() -> Self {
        Self {
            leases: Vec::new(),
            next_token: 1,
        }
    }

    pub(crate) fn open(
        &mut self,
        key: CellId,
        physical_path: String,
    ) -> Result<u64, SystemKeyLeaseError> {
        let token = self.next_token;
        if token == 0 {
            return Err(SystemKeyLeaseError::Exhausted);
        }
        self.next_token = token.checked_add(1).unwrap_or(0);
        let lease = SystemKeyLease {
            token,
            key,
            physical_path,
        };
        if let Some(slot) = self.leases.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(lease);
            return Ok(token);
        }
        self.leases
            .try_reserve_exact(1)
            .map_err(|_| SystemKeyLeaseError::Exhausted)?;
        self.leases.push(Some(lease));
        Ok(token)
    }

    pub(crate) fn get(&self, token: u64) -> Option<&SystemKeyLease> {
        (token != 0)
            .then(|| {
                self.leases
                    .iter()
                    .flatten()
                    .find(|lease| lease.token == token)
            })
            .flatten()
    }

    pub(crate) fn close(&mut self, token: u64) -> Result<(), SystemKeyLeaseError> {
        let Some(slot) = self
            .leases
            .iter_mut()
            .find(|slot| slot.as_ref().is_some_and(|lease| lease.token == token))
        else {
            return Err(SystemKeyLeaseError::Invalid);
        };
        *slot = None;
        Ok(())
    }

    pub(crate) fn invalidate(&mut self) {
        self.leases.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leases_are_opaque_exact_and_reuse_storage_without_reusing_tokens() {
        let mut bank = SystemKeyLeaseBank::new();
        let first = bank
            .open(
                CellId(17),
                String::from(r"\Registry\Machine\System\ControlSet002"),
            )
            .unwrap();
        assert_eq!(bank.get(first).unwrap().key, CellId(17));
        bank.close(first).unwrap();
        assert!(bank.get(first).is_none());

        let second = bank
            .open(CellId(23), String::from(r"\Registry\Machine\System\Select"))
            .unwrap();
        assert_ne!(second, first);
        assert_eq!(bank.get(second).unwrap().key, CellId(23));
        assert_eq!(bank.close(first), Err(SystemKeyLeaseError::Invalid));
    }

    #[test]
    fn mount_replacement_invalidates_every_lease() {
        let mut bank = SystemKeyLeaseBank::new();
        let token = bank.open(CellId(1), String::from("key")).unwrap();
        bank.invalidate();
        assert!(bank.get(token).is_none());
    }
}
