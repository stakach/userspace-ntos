//! Identity and admission policy for retained component service Calls.

use core::sync::atomic::{AtomicU64, Ordering};

/// Every service kind sharing one physical ingress must draw from this issuer.
/// Exhaustion is terminal: wrapping would make an old semantic tombstone alias a new Call.
pub struct ServiceWaitTokenIssuer {
    next: AtomicU64,
}

impl ServiceWaitTokenIssuer {
    pub const fn new() -> Self {
        Self { next: AtomicU64::new(1) }
    }

    pub fn issue(&self) -> Option<u64> {
        self.next.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| current.checked_add(1))
            .ok()
            .filter(|token| *token != 0)
    }
}

impl Default for ServiceWaitTokenIssuer {
    fn default() -> Self { Self::new() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceWaitOccupancy {
    /// A physical Call or Reply can still be consumed by this owner.
    InFlight,
    /// The physical Reply was acknowledged; only exact semantic ownership remains.
    ReplyAcknowledged,
    Retired,
}

impl ServiceWaitOccupancy {
    pub const fn blocks_new_call(self) -> bool {
        matches!(self, Self::InFlight)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_service_kinds_draw_disjoint_tokens() {
        let issuer = ServiceWaitTokenIssuer::new();
        let file = issuer.issue().unwrap();
        let source_pnp = issuer.issue().unwrap();
        let source_fsd = issuer.issue().unwrap();
        assert_eq!([file, source_pnp, source_fsd], [1, 2, 3]);
    }

    #[test]
    fn exhausted_sequence_never_wraps_to_an_old_token() {
        let issuer = ServiceWaitTokenIssuer { next: AtomicU64::new(u64::MAX) };
        assert_eq!(issuer.issue(), None);
        assert_eq!(issuer.issue(), None);
    }

    #[test]
    fn acknowledged_reply_does_not_occupy_reused_physical_dispatch() {
        assert!(ServiceWaitOccupancy::InFlight.blocks_new_call());
        assert!(!ServiceWaitOccupancy::ReplyAcknowledged.blocks_new_call());
        assert!(!ServiceWaitOccupancy::Retired.blocks_new_call());
    }
}
