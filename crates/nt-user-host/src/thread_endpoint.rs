//! Install a thread's fault endpoint directly in its owned CNode from a borrowed root source.

/// A construction request, not capability ownership. Copy preserves an existing badge; mint
/// supplies a new badge without allocating an intermediate root capability.
/// A borrowed source's endpoint kind and badge provenance remain the caller's responsibility;
/// numeric source validation cannot inspect the capability or authenticate an incoming message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadFaultEndpoint {
    /// Caller must establish an endpoint source with an already-valid endpoint-namespace badge.
    /// `is_valid` cannot inspect the source capability's kind or badge.
    Borrowed(u64),
    Badged { source: u64, badge: u64 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum EndpointInstallError<E> {
    InvalidSource,
    InvalidBadge,
    Backend(E),
}

/// The destination CNode owns the installed copy. No root allocation or deletion is needed.
pub trait ThreadEndpointBackend {
    type Error;
    fn copy(&mut self, cnode: u64, slot: u64, source: u64) -> Result<(), Self::Error>;
    fn mint(&mut self, cnode: u64, slot: u64, source: u64, badge: u64) -> Result<(), Self::Error>;
}

impl ThreadFaultEndpoint {
    pub const fn source(self) -> u64 {
        match self {
            Self::Borrowed(source) | Self::Badged { source, .. } => source,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.source() > 1
            && match self {
                Self::Borrowed(_) => true,
                Self::Badged { badge, .. } => {
                    nt_component_suspension::badge::valid_endpoint_badge(badge)
                }
            }
    }

    /// Install once into the caller-owned empty destination slot. Backend errors are returned
    /// unchanged; they never trigger a copy fallback or deletion of the borrowed source.
    pub fn install<B: ThreadEndpointBackend>(
        self,
        backend: &mut B,
        cnode: u64,
        slot: u64,
    ) -> Result<(), EndpointInstallError<B::Error>> {
        if self.source() <= 1 {
            return Err(EndpointInstallError::InvalidSource);
        }
        if !self.is_valid() {
            return Err(EndpointInstallError::InvalidBadge);
        }
        match self {
            Self::Borrowed(source) => backend.copy(cnode, slot, source),
            Self::Badged { source, badge } => backend.mint(cnode, slot, source, badge),
        }
        .map_err(EndpointInstallError::Backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[derive(Default)]
    struct Backend {
        calls: Vec<(u64, u64, u64, Option<u64>)>,
        error: Option<u64>,
    }

    impl ThreadEndpointBackend for Backend {
        type Error = u64;
        fn copy(&mut self, cnode: u64, slot: u64, source: u64) -> Result<(), u64> {
            self.calls.push((cnode, slot, source, None));
            self.error.map_or(Ok(()), Err)
        }
        fn mint(&mut self, cnode: u64, slot: u64, source: u64, badge: u64) -> Result<(), u64> {
            self.calls.push((cnode, slot, source, Some(badge)));
            self.error.map_or(Ok(()), Err)
        }
    }

    #[test]
    fn borrowed_endpoint_uses_copy_without_rebadging() {
        let mut backend = Backend::default();
        ThreadFaultEndpoint::Borrowed(42)
            .install(&mut backend, 100, 3)
            .unwrap();
        assert_eq!(backend.calls, [(100, 3, 42, None)]);
    }

    #[test]
    fn badge_is_minted_directly_into_the_destination() {
        for badge in [
            0,
            1,
            526,
            nt_component_suspension::badge::ENDPOINT_BADGE_MAX,
        ] {
            let mut backend = Backend::default();
            ThreadFaultEndpoint::Badged { source: 42, badge }
                .install(&mut backend, 100, 3)
                .unwrap();
            assert_eq!(backend.calls, [(100, 3, 42, Some(badge))]);
        }
    }

    #[test]
    fn invalid_sources_do_not_invoke_the_backend() {
        for source in [0, 1] {
            for request in [
                ThreadFaultEndpoint::Borrowed(source),
                ThreadFaultEndpoint::Badged { source, badge: 99 },
            ] {
                let mut backend = Backend::default();
                assert_eq!(
                    request.install(&mut backend, 100, 3),
                    Err(EndpointInstallError::InvalidSource)
                );
                assert!(backend.calls.is_empty());
            }
        }
    }

    #[test]
    fn reserved_badges_fail_before_any_capability_effect() {
        use nt_component_suspension::badge::{IRQ_BADGE, TIMER_BADGE};
        for badge in [
            IRQ_BADGE,
            IRQ_BADGE | 1,
            TIMER_BADGE,
            TIMER_BADGE | 526,
            1 << 63,
            u64::MAX,
        ] {
            let mut backend = Backend::default();
            let endpoint = ThreadFaultEndpoint::Badged { source: 42, badge };
            assert!(!endpoint.is_valid());
            assert_eq!(
                endpoint.install(&mut backend, 100, 3),
                Err(EndpointInstallError::InvalidBadge)
            );
            assert!(backend.calls.is_empty());
        }
    }

    #[test]
    fn failed_copy_or_mint_is_not_retried_or_replaced_with_a_fallback() {
        for request in [
            ThreadFaultEndpoint::Borrowed(42),
            ThreadFaultEndpoint::Badged {
                source: 42,
                badge: 99,
            },
        ] {
            let mut backend = Backend {
                error: Some(17),
                ..Backend::default()
            };
            assert_eq!(
                request.install(&mut backend, 100, 3),
                Err(EndpointInstallError::Backend(17))
            );
            assert_eq!(backend.calls.len(), 1);
        }
    }
}
