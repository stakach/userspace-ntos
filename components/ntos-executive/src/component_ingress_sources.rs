//! Physical source attribution for shared ingress; never capability or execution authority.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhysicalDomain {
    Provider {
        catalog: nt_provider_wait::CatalogIdentity,
        domain: nt_provider_wait::ProviderDomainIdentity,
    },
    Hosted(nt_io_manager::HostedDomainIdentity),
}

impl PhysicalDomain {
    fn is_valid(self) -> bool {
        match self {
            Self::Provider { domain, .. } => domain.is_valid(),
            Self::Hosted(identity) => identity.domain_id.raw() != 0 && identity.cookie != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhysicalSourceKind {
    Primary,
    DispatchWorker { ordinal: u64 },
    SystemThread { handle: u64 },
    Interrupt(nt_hosted_runtime::HostedIrqLaneIdentity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalSource {
    pub domain: PhysicalDomain,
    pub kind: PhysicalSourceKind,
    pub pml4: u64,
    pub tcb: u64,
}

impl PhysicalSource {
    fn is_valid(self) -> bool {
        if !self.domain.is_valid() || self.pml4 == 0 || self.tcb == 0 {
            return false;
        }
        match self.kind {
            PhysicalSourceKind::Primary => true,
            PhysicalSourceKind::DispatchWorker { ordinal } => ordinal != 0,
            PhysicalSourceKind::SystemThread { handle } => handle != 0,
            PhysicalSourceKind::Interrupt(irq) => match self.domain {
                PhysicalDomain::Hosted(domain) => {
                    irq.lane_generation != 0
                        && irq.domain_id == domain.domain_id.raw()
                        && irq.domain_cookie == domain.cookie
                }
                PhysicalDomain::Provider { .. } => false,
            },
        }
    }
}

pub(crate) use nt_component_suspension::source_registry::IngressSourceIdentity;
pub(crate) type IngressSourceRegistry =
    nt_component_suspension::source_registry::IngressSourceRegistry<PhysicalSource>;

impl nt_component_suspension::source_registry::IngressSource for PhysicalSource {
    type Domain = PhysicalDomain;
    type Kind = PhysicalSourceKind;
    fn domain(self) -> Self::Domain {
        self.domain
    }
    fn kind(self) -> Self::Kind {
        self.kind
    }
    fn tcb(self) -> u64 {
        self.tcb
    }
    fn vspace(self) -> u64 {
        self.pml4
    }
    fn is_valid(self) -> bool {
        PhysicalSource::is_valid(self)
    }
}
