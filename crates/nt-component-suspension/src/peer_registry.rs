//! Registration and retention for a future shared component ingress endpoint.
//!
//! Routes are metadata, not Reply-binding, domain-liveness or execution authority. The native
//! owner must validate canonical physical lifetimes and retain the corresponding capabilities.

use crate::{badge::ENDPOINT_BADGE_MAX, LaneHandle};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_BADGE: AtomicU64 = AtomicU64::new(1);

/// An opaque projection of a canonical physical domain, never logical request attribution.
/// Domain IDs must come from one namespace owned by the registry's native adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    pub domain: u64,
    pub domain_generation: u64,
    /// Root-canonical TCB identity/capability retained through retirement, never a local cptr.
    pub executor: u64,
    pub lane: LaneHandle,
}

impl PeerIdentity {
    fn is_valid(self) -> bool {
        self.domain != 0
            && self.domain_generation != 0
            && self.executor != 0
            && self.lane.is_valid()
    }

    fn conflicts(self, other: Self) -> bool {
        self.executor == other.executor
            || (self.domain == other.domain
                && self.domain_generation == other.domain_generation
                && self.lane == other.lane)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerRoute {
    endpoint: u64,
    badge: u64,
    identity: PeerIdentity,
}

impl PeerRoute {
    pub const fn endpoint(self) -> u64 {
        self.endpoint
    }
    pub const fn badge(self) -> u64 {
        self.badge
    }
    pub const fn identity(self) -> PeerIdentity {
        self.identity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerPhase {
    Staged,
    Active,
    Retiring,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerError {
    InvalidIdentity,
    DuplicatePeer,
    NoCapacity,
    BadgeExhausted,
    WrongOwner,
    WrongPhase,
    RetainedWork,
}

/// Dropping this ticket leaves the staged reservation intact rather than reusing its identity.
///
/// ```compile_fail
/// use nt_component_suspension::peer_registry::PeerRegistration;
/// fn duplicate(ticket: PeerRegistration) { let _ = ticket.clone(); }
/// ```
#[must_use = "publish or abort this exact staged registration"]
#[derive(Debug)]
pub struct PeerRegistration {
    route: Option<PeerRoute>,
}

impl PeerRegistration {
    pub const fn route(&self) -> Option<PeerRoute> {
        self.route
    }
}

/// Dropping this ticket keeps the registry retention outstanding. Only acknowledged completion
/// or completed cancellation permits release. It cannot be cloned or manufactured from a route.
///
/// ```compile_fail
/// use nt_component_suspension::peer_registry::PeerRetention;
/// fn duplicate(ticket: PeerRetention) { let _ = ticket.clone(); }
/// ```
#[must_use = "retain this ticket until the received work is completed or cancelled"]
#[derive(Debug)]
pub struct PeerRetention {
    route: Option<PeerRoute>,
}

impl PeerRetention {
    pub const fn route(&self) -> Option<PeerRoute> {
        self.route
    }
}

struct Entry {
    route: PeerRoute,
    phase: PeerPhase,
    retained: usize,
}

pub struct PeerRegistry {
    endpoint: u64,
    capacity: usize,
    entries: Vec<Entry>,
}

impl PeerRegistry {
    pub const fn endpoint(&self) -> u64 {
        self.endpoint
    }

    pub const fn new(endpoint: u64, capacity: usize) -> Self {
        Self {
            endpoint,
            capacity,
            entries: Vec::new(),
        }
    }

    pub fn stage(&mut self, identity: PeerIdentity) -> Result<PeerRegistration, PeerError> {
        self.stage_with_counter(identity, &NEXT_BADGE)
    }

    fn stage_with_counter(
        &mut self,
        identity: PeerIdentity,
        counter: &AtomicU64,
    ) -> Result<PeerRegistration, PeerError> {
        if self.endpoint == 0 || !identity.is_valid() {
            return Err(PeerError::InvalidIdentity);
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.route.identity.conflicts(identity))
        {
            return Err(PeerError::DuplicatePeer);
        }
        if self.entries.len() >= self.capacity {
            return Err(PeerError::NoCapacity);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| PeerError::NoCapacity)?;
        // Burn identities forever, including aborted registrations and destroyed registries.
        let badge = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                (next != 0 && next <= ENDPOINT_BADGE_MAX).then(|| next + 1)
            })
            .map_err(|_| PeerError::BadgeExhausted)?;
        let route = PeerRoute {
            endpoint: self.endpoint,
            badge,
            identity,
        };
        self.entries.push(Entry {
            route,
            phase: PeerPhase::Staged,
            retained: 0,
        });
        Ok(PeerRegistration { route: Some(route) })
    }

    fn index(&self, route: PeerRoute) -> Result<usize, PeerError> {
        self.entries
            .iter()
            .position(|entry| entry.route == route)
            .ok_or(PeerError::WrongOwner)
    }

    /// Publish only after native capability mint/installation succeeds. This does not resume a TCB.
    pub fn publish(&mut self, registration: &mut PeerRegistration) -> Result<PeerRoute, PeerError> {
        let route = registration.route.ok_or(PeerError::WrongOwner)?;
        let index = self.index(route)?;
        if self.entries[index].phase != PeerPhase::Staged {
            return Err(PeerError::WrongPhase);
        }
        self.entries[index].phase = PeerPhase::Active;
        registration.route = None;
        Ok(route)
    }

    /// Remove routing reservation only; native code still owns cleanup of partially installed caps.
    /// A leftover alias can never name a future peer because this badge is permanently burned.
    pub fn abort(&mut self, registration: &mut PeerRegistration) -> Result<(), PeerError> {
        let route = registration.route.ok_or(PeerError::WrongOwner)?;
        let index = self.index(route)?;
        if self.entries[index].phase != PeerPhase::Staged {
            return Err(PeerError::WrongPhase);
        }
        self.entries.swap_remove(index);
        registration.route = None;
        Ok(())
    }

    /// Only active peers are candidates for new routing; revalidate physical liveness separately.
    pub fn resolve(&self, badge: u64) -> Option<PeerRoute> {
        self.route_in_phase(badge, PeerPhase::Active)
    }

    /// Resolve late arrivals for cancellation/draining without a second identity map. This grants
    /// neither execution nor Reply authority; validate the exact native TCB binding and lifetime.
    pub fn resolve_retiring(&self, badge: u64) -> Option<PeerRoute> {
        self.route_in_phase(badge, PeerPhase::Retiring)
    }

    fn route_in_phase(&self, badge: u64, phase: PeerPhase) -> Option<PeerRoute> {
        self.entries
            .iter()
            .find(|entry| entry.route.badge == badge && entry.phase == phase)
            .map(|entry| entry.route)
    }

    pub fn state(&self, route: PeerRoute) -> Result<(PeerPhase, usize), PeerError> {
        let entry = &self.entries[self.index(route)?];
        Ok((entry.phase, entry.retained))
    }

    /// Retiring peers may still have arrivals to cancel/drain. Retention never grants execution.
    pub fn retain(&mut self, route: PeerRoute) -> Result<PeerRetention, PeerError> {
        let index = self.index(route)?;
        let entry = &mut self.entries[index];
        if entry.phase == PeerPhase::Staged {
            return Err(PeerError::WrongPhase);
        }
        entry.retained = entry.retained.checked_add(1).ok_or(PeerError::NoCapacity)?;
        Ok(PeerRetention { route: Some(route) })
    }

    pub fn release(&mut self, retention: &mut PeerRetention) -> Result<(), PeerError> {
        let route = retention.route.ok_or(PeerError::WrongOwner)?;
        let index = self.index(route)?;
        let retained = self.entries[index]
            .retained
            .checked_sub(1)
            .ok_or(PeerError::WrongOwner)?;
        self.entries[index].retained = retained;
        retention.route = None;
        Ok(())
    }

    /// Stop new route lookup while existing owned work is drained. This is not capability revocation.
    pub fn begin_retirement(&mut self, route: PeerRoute) -> Result<(), PeerError> {
        let index = self.index(route)?;
        if self.entries[index].phase != PeerPhase::Active {
            return Err(PeerError::WrongPhase);
        }
        self.entries[index].phase = PeerPhase::Retiring;
        Ok(())
    }

    /// The native owner must also stop/revoke senders and drain queued arrivals and continuations.
    /// A zero retention count alone does not establish those external conditions.
    pub fn finish_retirement(&mut self, route: PeerRoute) -> Result<(), PeerError> {
        let index = self.index(route)?;
        let entry = &self.entries[index];
        if entry.phase != PeerPhase::Retiring {
            return Err(PeerError::WrongPhase);
        }
        if entry.retained != 0 {
            return Err(PeerError::RetainedWork);
        }
        self.entries.swap_remove(index);
        Ok(())
    }
}

#[cfg(test)]
#[path = "peer_registry_tests.rs"]
mod tests;
