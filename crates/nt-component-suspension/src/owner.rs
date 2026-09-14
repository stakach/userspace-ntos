//! Shared caller authority and teardown scopes for component continuations.

use crate::LaneHandle;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspensionHostedClient {
    pub client_pi: u32,
    pub client_generation: u64,
    pub client_tid: u64,
    pub client_badge: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuspensionCaller {
    Hosted(SuspensionHostedClient),
    Kernel { lane: LaneHandle },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspensionOwner {
    pub provider_domain: u64,
    pub provider_generation: u64,
    /// Hosted callback dispatch ID, or the active LaneDispatchIdentity epoch for a kernel caller.
    pub dispatch_id: u64,
    pub caller: SuspensionCaller,
}

impl SuspensionOwner {
    pub const fn is_valid(self) -> bool {
        self.provider_domain != 0
            && self.provider_generation != 0
            && self.dispatch_id != 0
            && match self.caller {
                SuspensionCaller::Hosted(client) => {
                    client.client_generation != 0
                        && client.client_tid != 0
                        && client.client_badge != 0
                }
                SuspensionCaller::Kernel { lane } => lane.is_valid(),
            }
    }

    pub const fn hosted_client(self) -> Option<SuspensionHostedClient> {
        match self.caller {
            SuspensionCaller::Hosted(client) => Some(client),
            SuspensionCaller::Kernel { .. } => None,
        }
    }

    /// Duplicate-dispatch identity, not authorization. Admission and resume still require the
    /// complete owner. Hosted callback IDs and kernel lane epochs occupy distinct namespaces.
    pub const fn same_dispatch(self, other: Self) -> bool {
        if self.provider_domain != other.provider_domain
            || self.provider_generation != other.provider_generation
            || self.dispatch_id != other.dispatch_id
        {
            return false;
        }
        match (self.caller, other.caller) {
            (SuspensionCaller::Hosted(_), SuspensionCaller::Hosted(_)) => true,
            (SuspensionCaller::Kernel { lane }, SuspensionCaller::Kernel { lane: other }) => {
                lane.index == other.index && lane.generation == other.generation
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuspensionScope {
    Provider {
        domain: u64,
        generation: u64,
    },
    Process {
        domain: u64,
        provider_generation: u64,
        client_pi: u32,
        client_generation: u64,
    },
    Thread {
        domain: u64,
        provider_generation: u64,
        client_pi: u32,
        client_generation: u64,
        client_tid: u64,
        client_badge: u64,
    },
    KernelLane {
        domain: u64,
        provider_generation: u64,
        lane: LaneHandle,
    },
}

impl SuspensionScope {
    pub const fn is_valid(self) -> bool {
        match self {
            Self::Provider { domain, generation } => domain != 0 && generation != 0,
            Self::Process {
                domain,
                provider_generation,
                client_generation,
                ..
            } => domain != 0 && provider_generation != 0 && client_generation != 0,
            Self::Thread {
                domain,
                provider_generation,
                client_generation,
                client_tid,
                client_badge,
                ..
            } => {
                domain != 0
                    && provider_generation != 0
                    && client_generation != 0
                    && client_tid != 0
                    && client_badge != 0
            }
            Self::KernelLane {
                domain,
                provider_generation,
                lane,
            } => domain != 0 && provider_generation != 0 && lane.is_valid(),
        }
    }

    pub const fn matches(self, owner: SuspensionOwner) -> bool {
        match self {
            Self::Provider { domain, generation } => {
                owner.provider_domain == domain && owner.provider_generation == generation
            }
            Self::Process {
                domain,
                provider_generation,
                client_pi,
                client_generation,
            } => match owner.caller {
                SuspensionCaller::Hosted(client) => {
                    owner.provider_domain == domain
                        && owner.provider_generation == provider_generation
                        && client.client_pi == client_pi
                        && client.client_generation == client_generation
                }
                SuspensionCaller::Kernel { .. } => false,
            },
            Self::Thread {
                domain,
                provider_generation,
                client_pi,
                client_generation,
                client_tid,
                client_badge,
            } => match owner.caller {
                SuspensionCaller::Hosted(client) => {
                    owner.provider_domain == domain
                        && owner.provider_generation == provider_generation
                        && client.client_pi == client_pi
                        && client.client_generation == client_generation
                        && client.client_tid == client_tid
                        && client.client_badge == client_badge
                }
                SuspensionCaller::Kernel { .. } => false,
            },
            Self::KernelLane {
                domain,
                provider_generation,
                lane,
            } => match owner.caller {
                SuspensionCaller::Kernel { lane: owned } => {
                    owner.provider_domain == domain
                        && owner.provider_generation == provider_generation
                        && owned.index == lane.index
                        && owned.generation == lane.generation
                }
                SuspensionCaller::Hosted(_) => false,
            },
        }
    }
}
