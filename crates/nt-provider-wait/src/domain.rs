use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDomainIdentity {
    pub domain: u64,
    pub generation: u64,
}

impl ProviderDomainIdentity {
    pub const fn is_valid(self) -> bool {
        self.domain != 0 && self.generation != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDomainError {
    InvalidIdentity,
    StaleIdentity,
    ActiveWaits,
    GenerationExhausted,
    NoCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderDomainRecord {
    generation: u64,
    live: bool,
}

/// Allocates reusable provider-domain slots while fencing every reuse by generation.
pub struct ProviderDomainCatalog {
    records: Vec<ProviderDomainRecord>,
}

impl ProviderDomainCatalog {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn register(&mut self) -> Result<ProviderDomainIdentity, ProviderDomainError> {
        if let Some((slot, record)) = self
            .records
            .iter_mut()
            .enumerate()
            .find(|(_, record)| !record.live)
        {
            let generation = record
                .generation
                .checked_add(1)
                .ok_or(ProviderDomainError::GenerationExhausted)?;
            *record = ProviderDomainRecord {
                generation,
                live: true,
            };
            return Ok(ProviderDomainIdentity {
                domain: slot as u64 + 1,
                generation,
            });
        }
        self.records
            .try_reserve(1)
            .map_err(|_| ProviderDomainError::NoCapacity)?;
        self.records.push(ProviderDomainRecord {
            generation: 1,
            live: true,
        });
        Ok(ProviderDomainIdentity {
            domain: self.records.len() as u64,
            generation: 1,
        })
    }

    pub fn contains(&self, identity: ProviderDomainIdentity) -> bool {
        let Some(slot) = identity.domain.checked_sub(1) else {
            return false;
        };
        usize::try_from(slot)
            .ok()
            .and_then(|slot| self.records.get(slot))
            .is_some_and(|record| record.live && record.generation == identity.generation)
    }

    pub fn retire(
        &mut self,
        identity: ProviderDomainIdentity,
        active_waits: usize,
    ) -> Result<(), ProviderDomainError> {
        if !identity.is_valid() {
            return Err(ProviderDomainError::InvalidIdentity);
        }
        if active_waits != 0 {
            return Err(ProviderDomainError::ActiveWaits);
        }
        let slot =
            usize::try_from(identity.domain - 1).map_err(|_| ProviderDomainError::StaleIdentity)?;
        let record = self
            .records
            .get_mut(slot)
            .ok_or(ProviderDomainError::StaleIdentity)?;
        if !record.live || record.generation != identity.generation {
            return Err(ProviderDomainError::StaleIdentity);
        }
        record.live = false;
        Ok(())
    }
}

impl Default for ProviderDomainCatalog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuse_changes_generation_and_rejects_stale_identity() {
        let mut catalog = ProviderDomainCatalog::new();
        let first = catalog.register().unwrap();
        assert!(catalog.contains(first));
        catalog.retire(first, 0).unwrap();
        assert!(!catalog.contains(first));
        let second = catalog.register().unwrap();
        assert_eq!(second.domain, first.domain);
        assert_eq!(second.generation, first.generation + 1);
        assert_eq!(
            catalog.retire(first, 0),
            Err(ProviderDomainError::StaleIdentity)
        );
    }

    #[test]
    fn active_waits_fence_domain_retirement() {
        let mut catalog = ProviderDomainCatalog::new();
        let identity = catalog.register().unwrap();
        assert_eq!(
            catalog.retire(identity, 1),
            Err(ProviderDomainError::ActiveWaits)
        );
        assert!(catalog.contains(identity));
        catalog.retire(identity, 0).unwrap();
    }
}
