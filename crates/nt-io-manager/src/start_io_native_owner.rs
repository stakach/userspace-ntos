//! Exact native pending-node identity for a future StartIo queue/current adapter.
//!
//! The provider's pending node remains the packet owner. This value is an observation of its
//! generation and root-issued source ticket, not a second queue or a source allocation pin.
//! It may be held across callbacks only together with the canonical node owner's phase claim.

use crate::retained_query_path_forward::SourceIrpTicket;
use crate::{HostedDevicePointerRegistration, HostedDomainIdentity};

/// Ordinary pending IRPs have no source ticket. A half-published ticket is never ordinary.
pub fn completion_source_ticket(
    domain: HostedDomainIdentity,
    id: u64,
    generation: u64,
) -> Result<Option<SourceIrpTicket>, ()> {
    if id == 0 && generation == 0 {
        return Ok(None);
    }
    SourceIrpTicket::new(domain, id, generation).map(Some).ok_or(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingStartIoNodeIdentity {
    pub node: u64,
    pub generation: u64,
    pub canonical_irp_id: u64,
    pub raw_irp: u64,
    pub source: SourceIrpTicket,
}

impl PendingStartIoNodeIdentity {
    pub fn new(
        node: u64,
        generation: u64,
        canonical_irp_id: u64,
        raw_irp: u64,
        source: SourceIrpTicket,
    ) -> Option<Self> {
        (node != 0
            && node & 7 == 0
            && generation != 0
            && generation & 0xff == 0
            && canonical_irp_id != 0
            && raw_irp != 0
            && raw_irp & 7 == 0)
            .then_some(Self { node, generation, canonical_irp_id, raw_irp, source })
    }

    pub fn matches(self, observed: Self) -> bool {
        self == observed
    }
}

/// Adds the exact registered DEVICE_OBJECT projection. The registration is an observation;
/// native code must retain the matching projection reference until this obligation settles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingStartIoQueueIdentity {
    pub packet: PendingStartIoNodeIdentity,
    pub device: HostedDevicePointerRegistration,
}

impl PendingStartIoQueueIdentity {
    pub fn new(packet: PendingStartIoNodeIdentity, device: HostedDevicePointerRegistration) -> Option<Self> {
        (device.address() != 0 && device.generation() != 0).then_some(Self { packet, device })
    }

    pub fn matches(self, observed: Self) -> bool {
        self == observed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HostedDomainId, HostedDomainIdentity};

    fn ticket() -> SourceIrpTicket {
        SourceIrpTicket::new(
            HostedDomainIdentity { domain_id: HostedDomainId(7), cookie: 11 },
            19,
            23,
        ).unwrap()
    }

    #[test]
    fn reused_node_or_raw_address_requires_exact_generation_and_ticket() {
        let first = PendingStartIoNodeIdentity::new(0x1000, 0x100, 31, 0x2000, ticket()).unwrap();
        let newer = PendingStartIoNodeIdentity::new(0x1000, 0x200, 32, 0x2000, ticket()).unwrap();
        assert!(!first.matches(newer));
        let new_ticket = SourceIrpTicket::new(ticket().domain, 19, 24).unwrap();
        let same_node_new_source = PendingStartIoNodeIdentity::new(0x1000, 0x100, 31, 0x2000, new_ticket).unwrap();
        assert!(!first.matches(same_node_new_source));
        assert!(first.matches(first));
    }

    #[test]
    fn incomplete_pending_node_cannot_be_admitted() {
        for (node, generation, canonical, raw) in [
            (0, 0x100, 31, 0x2000),
            (0x1001, 0x100, 31, 0x2000),
            (0x1000, 0, 31, 0x2000),
            (0x1000, 0x101, 31, 0x2000),
            (0x1000, 0x100, 0, 0x2000),
            (0x1000, 0x100, 31, 0),
            (0x1000, 0x100, 31, 0x2001),
        ] {
            assert!(PendingStartIoNodeIdentity::new(node, generation, canonical, raw, ticket()).is_none());
        }
    }

    #[test]
    fn completion_claim_distinguishes_ordinary_and_root_ticketed_sources() {
        let domain = ticket().domain;
        assert_eq!(completion_source_ticket(domain, 0, 0), Ok(None));
        assert_eq!(completion_source_ticket(domain, 19, 23), Ok(Some(ticket())));
        assert_eq!(completion_source_ticket(domain, 19, 0), Err(()));
        assert_eq!(completion_source_ticket(domain, 0, 23), Err(()));
        assert_eq!(completion_source_ticket(HostedDomainIdentity::default(), 19, 23), Err(()));
    }
}
