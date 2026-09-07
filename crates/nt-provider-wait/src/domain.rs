use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_CATALOG: AtomicU64 = AtomicU64::new(1);

/// Exact catalog instance, preserved across moves and independent of reusable domain slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogIdentity(u64);

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
    identity: Option<CatalogIdentity>,
}

impl ProviderDomainCatalog {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            identity: None,
        }
    }

    pub fn register(&mut self) -> Result<ProviderDomainIdentity, ProviderDomainError> {
        self.register_with_counter(&NEXT_CATALOG)
    }

    fn register_with_counter(
        &mut self,
        counter: &AtomicU64,
    ) -> Result<ProviderDomainIdentity, ProviderDomainError> {
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
        let identity = match self.identity {
            Some(identity) => identity,
            None => CatalogIdentity(
                counter
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        if value == 0 {
                            None
                        } else {
                            value.checked_add(1)
                        }
                    })
                    .map_err(|_| ProviderDomainError::GenerationExhausted)?,
            ),
        };
        // All fallible work precedes publication of either the catalog or its first domain.
        self.identity = Some(identity);
        self.records.push(ProviderDomainRecord {
            generation: 1,
            live: true,
        });
        Ok(ProviderDomainIdentity {
            domain: self.records.len() as u64,
            generation: 1,
        })
    }

    /// None until the first successful registration. Retirement never resets this identity.
    pub const fn identity(&self) -> Option<CatalogIdentity> {
        self.identity
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

    #[test]
    fn independent_catalogs_with_colliding_domains_have_distinct_identity() {
        let mut first = ProviderDomainCatalog::new();
        let mut second = ProviderDomainCatalog::new();
        assert_eq!(first.identity(), None);
        let first_domain = first.register().unwrap();
        let second_domain = second.register().unwrap();
        assert_eq!(first_domain, second_domain);
        assert_ne!(first.identity(), second.identity());
        let identity = first.identity();
        let mut moved = alloc::boxed::Box::new(first);
        assert_eq!(moved.identity(), identity);
        moved.retire(first_domain, 0).unwrap();
        assert_eq!(moved.identity(), identity);
        let replacement = moved.register().unwrap();
        assert_ne!(replacement, first_domain);
        assert_eq!(moved.identity(), identity);
    }

    #[test]
    fn exhausted_nonce_never_publishes_catalog_or_domain() {
        let mut catalog = ProviderDomainCatalog::new();
        for value in [0, u64::MAX] {
            let counter = AtomicU64::new(value);
            assert_eq!(
                catalog.register_with_counter(&counter),
                Err(ProviderDomainError::GenerationExhausted)
            );
            assert_eq!(catalog.identity(), None);
            assert!(catalog.records.is_empty());
            assert_eq!(counter.load(Ordering::Relaxed), value);
        }
        let first = catalog.register().unwrap();
        let identity = catalog.identity();
        let counter = AtomicU64::new(u64::MAX);
        catalog.register_with_counter(&counter).unwrap();
        catalog.retire(first, 0).unwrap();
        catalog.register_with_counter(&counter).unwrap();
        assert_eq!(catalog.identity(), identity);
    }
}
