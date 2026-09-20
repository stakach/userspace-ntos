//! Physical transport identity retained across hosted-driver execution.

use crate::{HostedDomainId, HostedDomainIdentity};

/// The address-space owner, not a dependent driver's logical completion-attribution domain.
/// Reply objects rotate independently and must be checked by the native owner at each dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedTransportIdentity {
    pub domain: HostedDomainIdentity,
    pub endpoint: u64,
    pub vspace: u64,
    pub shared: u64,
}

impl HostedTransportIdentity {
    /// Numeric equality alone must not authenticate an absent domain or an empty transport.
    pub fn matches_live(self, live: Self) -> bool {
        self.domain.domain_id != HostedDomainId::NULL
            && self.domain.cookie != 0
            && self.endpoint != 0
            && self.vspace != 0
            && self.shared != 0
            && self == live
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> HostedTransportIdentity {
        HostedTransportIdentity {
            domain: HostedDomainIdentity {
                domain_id: HostedDomainId(12),
                cookie: 34,
            },
            endpoint: 56,
            vspace: 78,
            shared: 90,
        }
    }

    #[test]
    fn reused_transport_addresses_do_not_authenticate_a_replacement_domain() {
        let captured = identity();
        assert!(captured.matches_live(captured));
        let mut replacement = captured;
        replacement.domain.cookie += 1;
        assert!(!captured.matches_live(replacement));
        replacement = captured;
        replacement.domain.domain_id = HostedDomainId(13);
        assert!(!captured.matches_live(replacement));
    }

    #[test]
    fn every_physical_transport_field_must_match() {
        let captured = identity();
        for field in 0..3 {
            let mut live = captured;
            match field {
                0 => live.endpoint += 1,
                1 => live.vspace += 1,
                _ => live.shared += 1,
            }
            assert!(!captured.matches_live(live));
            assert!(!live.matches_live(captured));
        }
    }

    #[test]
    fn equal_empty_fields_do_not_form_a_valid_identity() {
        for field in 0..5 {
            let mut invalid = identity();
            match field {
                0 => invalid.domain.domain_id = HostedDomainId::NULL,
                1 => invalid.domain.cookie = 0,
                2 => invalid.endpoint = 0,
                3 => invalid.vspace = 0,
                _ => invalid.shared = 0,
            }
            assert!(!invalid.matches_live(invalid));
        }
    }
}
