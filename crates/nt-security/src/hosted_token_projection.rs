//! Exact, explicitly retained token pointers in an isolated hosted-driver domain.
//!
//! A pointer here is only a local projection of a canonical `TokenStore` object. The registry
//! owns a token reference until the projection is retired; consumers must also hold an exact
//! generation-bearing receipt while native code may still dereference the pointer.

use alloc::vec::Vec;
use core::num::NonZeroU64;

use crate::{AccessToken, Luid, TokenId, TokenStore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedTokenProjectionDomain {
    id: NonZeroU64,
    cookie: NonZeroU64,
}

impl HostedTokenProjectionDomain {
    pub fn new(id: u64, cookie: u64) -> Option<Self> {
        Some(Self {
            id: NonZeroU64::new(id)?,
            cookie: NonZeroU64::new(cookie)?,
        })
    }

    pub fn id(self) -> u64 {
        self.id.get()
    }

    pub fn cookie(self) -> u64 {
        self.cookie.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedTokenProjection {
    domain: HostedTokenProjectionDomain,
    address: NonZeroU64,
    generation: NonZeroU64,
    store_domain: NonZeroU64,
    token: TokenId,
    token_luid: Luid,
}

impl HostedTokenProjection {
    pub fn domain(self) -> HostedTokenProjectionDomain {
        self.domain
    }

    pub fn address(self) -> u64 {
        self.address.get()
    }

    pub fn generation(self) -> u64 {
        self.generation.get()
    }

    pub fn token(self) -> TokenId {
        self.token
    }

    pub fn token_luid(self) -> Luid {
        self.token_luid
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedTokenProjectionError {
    InvalidAddress,
    InvalidToken,
    WrongStore,
    AddressInUse,
    StaleProjection,
    Busy,
    InsufficientResources,
}

struct ProjectionRecord {
    identity: HostedTokenProjection,
    users: u32,
}

/// Binding and references are explicit. Dropping this registry does not release token references;
/// the native owner must retire every projection before destroying its token store or domain.
#[must_use = "retire every bound token projection explicitly"]
pub struct HostedTokenProjectionRegistry {
    records: Vec<ProjectionRecord>,
    next_generation: u64,
}

impl Default for HostedTokenProjectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HostedTokenProjectionRegistry {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            next_generation: 1,
        }
    }

    /// The native adapter must first prove that `token` belongs to its retained source subject
    /// and that `address` names live storage allocated in `domain`'s physical VSpace.
    pub fn bind(
        &mut self,
        tokens: &mut TokenStore,
        domain: HostedTokenProjectionDomain,
        address: u64,
        token: TokenId,
    ) -> Result<HostedTokenProjection, HostedTokenProjectionError> {
        let address = NonZeroU64::new(address).ok_or(HostedTokenProjectionError::InvalidAddress)?;
        if self.records.iter().any(|record| {
            record.identity.domain == domain && record.identity.address == address
        }) {
            return Err(HostedTokenProjectionError::AddressInUse);
        }
        let token_luid = tokens.statistics(token)
            .ok_or(HostedTokenProjectionError::InvalidToken)?
            .token_id;
        let next = self.next_generation.checked_add(1)
            .ok_or(HostedTokenProjectionError::InsufficientResources)?;
        self.records.try_reserve(1)
            .map_err(|_| HostedTokenProjectionError::InsufficientResources)?;
        let store_domain = NonZeroU64::new(tokens.acquire_subject_domain()
            .map_err(|_| HostedTokenProjectionError::InsufficientResources)?)
            .ok_or(HostedTokenProjectionError::WrongStore)?;
        tokens.retain(token).map_err(|_| HostedTokenProjectionError::InvalidToken)?;
        let identity = HostedTokenProjection {
            domain,
            address,
            generation: NonZeroU64::new(self.next_generation)
                .expect("nonzero projection sequence"),
            store_domain,
            token,
            token_luid,
        };
        self.next_generation = next;
        self.records.push(ProjectionRecord { identity, users: 0 });
        Ok(identity)
    }

    /// Locate the current receipt for a raw driver pointer. The receipt must still be checked
    /// against the source owner before it can authorize a cross-domain security operation.
    pub fn registration(
        &self,
        domain: HostedTokenProjectionDomain,
        address: u64,
    ) -> Option<HostedTokenProjection> {
        let address = NonZeroU64::new(address)?;
        self.records.iter()
            .find(|record| record.identity.domain == domain && record.identity.address == address)
            .map(|record| record.identity)
    }

    fn index(&self, identity: HostedTokenProjection) -> Result<usize, HostedTokenProjectionError> {
        self.records.iter().position(|record| record.identity == identity)
            .ok_or(HostedTokenProjectionError::StaleProjection)
    }

    /// Resolve against both the exact pointer generation and the canonical token-object LUID.
    pub fn resolve<'a>(
        &self,
        tokens: &'a TokenStore,
        identity: HostedTokenProjection,
    ) -> Result<&'a AccessToken, HostedTokenProjectionError> {
        self.index(identity)?;
        if tokens.subject_domain() != identity.store_domain.get() {
            return Err(HostedTokenProjectionError::WrongStore);
        }
        let statistics = tokens.statistics(identity.token)
            .ok_or(HostedTokenProjectionError::InvalidToken)?;
        if statistics.token_id != identity.token_luid || tokens.reference_count(identity.token) == Some(0) {
            return Err(HostedTokenProjectionError::InvalidToken);
        }
        tokens.get(identity.token).ok_or(HostedTokenProjectionError::InvalidToken)
    }

    /// Pin the exact projection during a forwarded IRP or token query. Retirement remains busy
    /// until each matching user explicitly dereferences it.
    pub fn reference(
        &mut self,
        tokens: &TokenStore,
        identity: HostedTokenProjection,
    ) -> Result<(), HostedTokenProjectionError> {
        self.resolve(tokens, identity)?;
        let index = self.index(identity)?;
        self.records[index].users = self.records[index].users.checked_add(1)
            .ok_or(HostedTokenProjectionError::InsufficientResources)?;
        Ok(())
    }

    pub fn dereference(
        &mut self,
        identity: HostedTokenProjection,
    ) -> Result<(), HostedTokenProjectionError> {
        let index = self.index(identity)?;
        let users = self.records[index].users;
        if users == 0 {
            return Err(HostedTokenProjectionError::StaleProjection);
        }
        self.records[index].users = users - 1;
        Ok(())
    }

    /// Release the registry's TokenStore reference only after all native users have quiesced.
    pub fn retire(
        &mut self,
        tokens: &mut TokenStore,
        identity: HostedTokenProjection,
    ) -> Result<(), HostedTokenProjectionError> {
        let index = self.index(identity)?;
        if self.records[index].users != 0 {
            return Err(HostedTokenProjectionError::Busy);
        }
        self.resolve(tokens, identity)?;
        tokens.release(identity.token)
            .map_err(|_| HostedTokenProjectionError::InvalidToken)?;
        self.records.swap_remove(index);
        Ok(())
    }
}

#[cfg(test)]
#[path = "hosted_token_projection_tests.rs"]
mod tests;
