//! Exact physical owner selection for a hosted IRQ lane's privileged CR8 fault.

use crate::HostedIrqLaneIdentity;

/// Root's retained physical IRQ lane, or an independently observed stopped fault source.
/// The native owner supplies these values from its lane, route, source and Reply registries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqCr8Source {
    pub lane: HostedIrqLaneIdentity,
    pub endpoint: u64,
    pub badge: u64,
    pub route_generation: u64,
    pub transaction: u64,
    pub tcb: u64,
    pub vspace: u64,
    pub reply: u64,
}

/// A fault may read the arena's IRQL only after all physical and generational owners agree.
pub fn select_hosted_irq_cr8_source(
    owner: HostedIrqCr8Source,
    fault: HostedIrqCr8Source,
) -> Option<HostedIrqLaneIdentity> {
    let lane = owner.lane;
    if HostedIrqLaneIdentity::new(lane.domain_id, lane.domain_cookie, lane.lane_generation)
        != Some(lane)
        || owner.endpoint == 0
        || owner.badge == 0
        || owner.route_generation == 0
        || owner.transaction == 0
        || owner.tcb == 0
        || owner.vspace == 0
        || owner.reply == 0
        || owner != fault
    {
        None
    } else {
        Some(lane)
    }
}
