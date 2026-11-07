//! Exact, retained authority for a bus interface returned by a hosted PnP provider.
//!
//! The wire reply contains only a lease id and canonical device id. Native integration must
//! project provider callbacks into the consumer domain and use this catalog for every invocation;
//! a provider `Context` address is never a consumer-domain pointer.

use alloc::vec::Vec;

use nt_pnp_abi::{BusInterfaceQueryReply, BusInterfaceQueryRequest, BUS_INTERFACE_STANDARD_X64_SIZE};
use nt_status::NtStatus;

use crate::{
    hosted_forward_target::HostedForwardTarget, DeviceId, HostedDevicePointerRegistration,
    HostedDomainIdentity, IoManager,
};

struct Lease {
    id: u64,
    consumer: HostedDomainIdentity,
    provider: HostedDevicePointerRegistration,
    target: HostedForwardTarget,
    references: u64,
    state: LeaseState,
    origin: LeaseOrigin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeaseOrigin {
    NativeProvider,
    ExecutivePci,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeaseState {
    Prepared,
    Active,
    Uncertain,
}

/// Broker-only identity of a provider query whose target is already pinned. It must remain with
/// the native query owner until a known terminal commits or aborts it, or an uncertain terminal
/// retains it. Its identifier is never a usable consumer interface before commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "resolve the native provider query before discarding its retained authority"]
pub struct PreparedBusInterfaceQuery {
    id: u64,
    consumer: HostedDomainIdentity,
    provider: HostedDevicePointerRegistration,
}

impl PreparedBusInterfaceQuery {
    pub const fn id(self) -> u64 {
        self.id
    }
}

/// The catalog is single-owner state, like `IoManager`. `next_id` never wraps or reuses an
/// identifier, so a late callback cannot acquire a later interface at the same slot.
#[derive(Default)]
pub struct BusInterfaceCatalog {
    next_id: u64,
    leases: Vec<Lease>,
}

impl BusInterfaceCatalog {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            leases: Vec::new(),
        }
    }

    /// Pin the exact provider and reserve a query identity before entering the native PDO.
    /// The provider's initial InterfaceReference, if successful, is owned by this row until a
    /// matching terminal commits, aborts, or quarantines it.
    pub fn prepare<P>(
        &mut self,
        io: &mut IoManager<P>,
        consumer: HostedDomainIdentity,
        provider: HostedDevicePointerRegistration,
        request: BusInterfaceQueryRequest,
    ) -> Result<PreparedBusInterfaceQuery, NtStatus> {
        request.validate().map_err(|_| NtStatus::INVALID_PARAMETER)?;
        if consumer.domain_id == provider.domain().domain_id
            || io.hosted_domain_identity(consumer.domain_id) != Some(consumer)
        {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let next = self.next_id.checked_add(1).ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        self.leases.try_reserve(1).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let target = HostedForwardTarget::capture(io, provider.domain(), provider.address())?;
        if target.registration() != provider {
            let mut target = target;
            target.release(io).expect("captured stale bus provider");
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let id = self.next_id;
        self.leases.push(Lease {
            id,
            consumer,
            provider,
            target,
            references: 0,
            state: LeaseState::Prepared,
            origin: LeaseOrigin::NativeProvider,
        });
        self.next_id = next;
        Ok(PreparedBusInterfaceQuery { id, consumer, provider })
    }

    fn prepared_index(&self, prepared: PreparedBusInterfaceQuery) -> Result<usize, NtStatus> {
        let index = self.leases.iter().position(|lease| lease.id == prepared.id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let lease = &self.leases[index];
        if lease.consumer != prepared.consumer || lease.provider != prepared.provider {
            return Err(NtStatus::ACCESS_DENIED);
        }
        match lease.state {
            LeaseState::Prepared => Ok(index),
            LeaseState::Active => Err(NtStatus::INVALID_PARAMETER),
            LeaseState::Uncertain => Err(NtStatus::DEVICE_BUSY),
        }
    }

    /// Return a provider-domain registration only to the broker driving this prepared query.
    /// The registration and any native callback pointers must not enter a consumer reply.
    pub fn prepared_provider<P>(
        &self,
        io: &IoManager<P>,
        prepared: PreparedBusInterfaceQuery,
    ) -> Result<HostedDevicePointerRegistration, NtStatus> {
        let index = self.prepared_index(prepared)?;
        let lease = &self.leases[index];
        if io.hosted_domain_identity(lease.consumer.domain_id) != Some(lease.consumer)
            || lease.target.validate(io)? != lease.provider.device_id()
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(lease.provider)
    }

    /// Publish a consumer-local lease only after the native provider returned success and its
    /// initial InterfaceReference was observed. No allocation is allowed after that effect.
    /// A stale validation result retains the row as uncertain for owner-specific recovery.
    pub fn commit<P>(
        &mut self,
        io: &IoManager<P>,
        prepared: PreparedBusInterfaceQuery,
    ) -> Result<BusInterfaceQueryReply, NtStatus> {
        let index = self.prepared_index(prepared)?;
        let validation = self.prepared_provider(io, prepared);
        if let Err(status) = validation {
            self.leases[index].state = LeaseState::Uncertain;
            return Err(status);
        }
        self.leases[index].references = 1;
        self.leases[index].state = LeaseState::Active;
        Ok(BusInterfaceQueryReply {
            size: BUS_INTERFACE_STANDARD_X64_SIZE,
            version: 1,
            lease_id: prepared.id,
            device_id: prepared.provider.device_id().raw(),
        })
    }

    /// Publish an interface implemented by the executive PCI bus service itself. The exact
    /// accepted PDO provider is pinned for identity and retirement safety, but no provider
    /// QueryInterface or provider callback is claimed to have run.
    pub fn issue_executive_pci<P>(
        &mut self,
        io: &mut IoManager<P>,
        consumer: HostedDomainIdentity,
        provider: HostedDevicePointerRegistration,
        request: BusInterfaceQueryRequest,
    ) -> Result<BusInterfaceQueryReply, NtStatus> {
        request.validate().map_err(|_| NtStatus::INVALID_PARAMETER)?;
        if consumer.domain_id == provider.domain().domain_id
            || io.hosted_domain_identity(consumer.domain_id) != Some(consumer)
        {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let next = self.next_id.checked_add(1).ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        self.leases.try_reserve(1).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let target = HostedForwardTarget::capture(io, provider.domain(), provider.address())?;
        if target.registration() != provider {
            let mut target = target;
            target.release(io).expect("captured stale PCI bus provider");
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let id = self.next_id;
        self.leases.push(Lease {
            id,
            consumer,
            provider,
            target,
            references: 1,
            state: LeaseState::Active,
            origin: LeaseOrigin::ExecutivePci,
        });
        self.next_id = next;
        Ok(BusInterfaceQueryReply {
            size: BUS_INTERFACE_STANDARD_X64_SIZE,
            version: 1,
            lease_id: id,
            device_id: provider.device_id().raw(),
        })
    }

    /// A known provider refusal acquired no initial interface reference. Release only the
    /// canonical target pin reserved by prepare; an uncertain release retains the row.
    pub fn abort<P>(
        &mut self,
        io: &mut IoManager<P>,
        prepared: PreparedBusInterfaceQuery,
    ) -> Result<(), NtStatus> {
        let index = self.prepared_index(prepared)?;
        if let Err(status) = self.leases[index].target.release(io) {
            self.leases[index].state = LeaseState::Uncertain;
            return Err(status);
        }
        self.leases.swap_remove(index);
        Ok(())
    }

    /// A lost terminal may have taken the provider's initial reference. Keep its target pinned
    /// and never retry the native query using this identity.
    pub fn retain_uncertain(
        &mut self,
        prepared: PreparedBusInterfaceQuery,
    ) -> Result<(), NtStatus> {
        let index = self.prepared_index(prepared)?;
        self.leases[index].state = LeaseState::Uncertain;
        Ok(())
    }

    fn lease_index<P>(
        &self,
        io: &IoManager<P>,
        consumer: HostedDomainIdentity,
        lease_id: u64,
    ) -> Result<usize, NtStatus> {
        if lease_id == 0 || io.hosted_domain_identity(consumer.domain_id) != Some(consumer) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let index = self.leases.iter().position(|lease| lease.id == lease_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let lease = &self.leases[index];
        if lease.consumer != consumer {
            return Err(NtStatus::ACCESS_DENIED);
        }
        match lease.state {
            LeaseState::Prepared => return Err(NtStatus::DEVICE_NOT_READY),
            LeaseState::Uncertain => return Err(NtStatus::DEVICE_BUSY),
            LeaseState::Active => {}
        }
        if lease.target.validate(io)? != lease.provider.device_id() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(index)
    }

    /// Privileged bridge-side lookup. Never serialize the returned registration into an
    /// interface reply; its address is meaningful only inside `provider.domain()`.
    pub fn provider<P>(
        &self,
        io: &IoManager<P>,
        consumer: HostedDomainIdentity,
        lease_id: u64,
    ) -> Result<HostedDevicePointerRegistration, NtStatus> {
        let index = self.lease_index(io, consumer, lease_id)?;
        Ok(self.leases[index].provider)
    }

    pub fn device<P>(
        &self,
        io: &IoManager<P>,
        consumer: HostedDomainIdentity,
        lease_id: u64,
    ) -> Result<DeviceId, NtStatus> {
        Ok(self.provider(io, consumer, lease_id)?.device_id())
    }

    /// The closure invokes the provider-local `InterfaceReference` exactly once. Reserve the
    /// local reference before the external effect; an uncertain result retains that reservation
    /// and must be quarantined by native integration, never replayed under this lease.
    pub fn reference<P>(
        &mut self,
        io: &IoManager<P>,
        consumer: HostedDomainIdentity,
        lease_id: u64,
        invoke: impl FnOnce(HostedDevicePointerRegistration) -> Result<(), NtStatus>,
    ) -> Result<(), NtStatus> {
        let index = self.lease_index(io, consumer, lease_id)?;
        let lease = &mut self.leases[index];
        if lease.origin != LeaseOrigin::NativeProvider {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        lease.references = lease.references.checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        let result = invoke(lease.provider);
        if result.is_err() {
            lease.state = LeaseState::Uncertain;
        }
        result
    }

    /// The provider-local `InterfaceDereference` must complete before the corresponding local
    /// count is retired. A refused or uncertain effect keeps the exact lease for reconciliation.
    pub fn dereference<P>(
        &mut self,
        io: &mut IoManager<P>,
        consumer: HostedDomainIdentity,
        lease_id: u64,
        invoke: impl FnOnce(HostedDevicePointerRegistration) -> Result<(), NtStatus>,
    ) -> Result<(), NtStatus> {
        let index = self.lease_index(io, consumer, lease_id)?;
        if self.leases[index].origin != LeaseOrigin::NativeProvider {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        let provider = self.leases[index].provider;
        if let Err(status) = invoke(provider) {
            self.leases[index].state = LeaseState::Uncertain;
            return Err(status);
        }
        if self.leases[index].references > 1 {
            self.leases[index].references -= 1;
            return Ok(());
        }
        if let Err(status) = self.leases[index].target.release(io) {
            self.leases[index].state = LeaseState::Uncertain;
            return Err(status);
        }
        self.leases.swap_remove(index);
        Ok(())
    }

    /// The executive PCI interface has no provider callback effect. Its canonical PDO pin
    /// remains until the last consumer-local reference is released.
    pub fn reference_executive_pci<P>(
        &mut self,
        io: &IoManager<P>,
        consumer: HostedDomainIdentity,
        lease_id: u64,
    ) -> Result<(), NtStatus> {
        let index = self.lease_index(io, consumer, lease_id)?;
        let lease = &mut self.leases[index];
        if lease.origin != LeaseOrigin::ExecutivePci {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        lease.references = lease.references.checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        Ok(())
    }

    pub fn dereference_executive_pci<P>(
        &mut self,
        io: &mut IoManager<P>,
        consumer: HostedDomainIdentity,
        lease_id: u64,
    ) -> Result<(), NtStatus> {
        let index = self.lease_index(io, consumer, lease_id)?;
        let lease = &mut self.leases[index];
        if lease.origin != LeaseOrigin::ExecutivePci {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        if lease.references > 1 {
            lease.references -= 1;
            return Ok(());
        }
        if let Err(status) = lease.target.release(io) {
            lease.state = LeaseState::Uncertain;
            return Err(status);
        }
        self.leases.swap_remove(index);
        Ok(())
    }

    pub fn active_count(&self) -> usize {
        self.leases.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceCharacteristics, DeviceFlags, DeviceType, MockDriverBackend, MockObjectPort};
    use alloc::boxed::Box;
    use nt_types::NtPath;

    fn fixture() -> (
        IoManager<MockObjectPort>, HostedDomainIdentity, HostedDomainIdentity,
        HostedDevicePointerRegistration,
    ) {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.create_driver(&NtPath::parse_str(r"\Driver\Pci").unwrap(),
            Box::new(MockDriverBackend::new())).unwrap();
        let device = io.create_device(driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::BUFFERED_IO, 0).unwrap();
        let provider = io.register_hosted_domain();
        let consumer = io.register_hosted_domain();
        let registration = io.bind_hosted_device_pointer(provider, 0x1000, device).unwrap();
        (io, provider, consumer, registration)
    }

    fn successful_query(
        catalog: &mut BusInterfaceCatalog,
        io: &mut IoManager<MockObjectPort>,
        consumer: HostedDomainIdentity,
        provider: HostedDevicePointerRegistration,
    ) -> BusInterfaceQueryReply {
        let prepared = catalog.prepare(io, consumer, provider,
            BusInterfaceQueryRequest::standard()).unwrap();
        catalog.commit(io, prepared).unwrap()
    }

    #[test]
    fn query_preparation_pins_provider_before_native_effect() {
        let (mut io, _, consumer, registration) = fixture();
        let baseline = io.device_reference_count(registration.device_id());
        let mut catalog = BusInterfaceCatalog::new();
        let prepared = catalog.prepare(&mut io, consumer, registration,
            BusInterfaceQueryRequest::standard()).unwrap();
        assert_eq!(io.device_reference_count(registration.device_id()), baseline + 1);
        assert_eq!(catalog.active_count(), 1);
        assert_eq!(catalog.prepared_provider(&io, prepared), Ok(registration));
        assert_eq!(catalog.provider(&io, consumer, prepared.id()),
            Err(NtStatus::DEVICE_NOT_READY));
        let reply = catalog.commit(&io, prepared).unwrap();
        assert_eq!(reply.lease_id, prepared.id());
        assert_eq!(catalog.provider(&io, consumer, reply.lease_id), Ok(registration));
    }

    #[test]
    fn known_query_refusal_releases_pin_without_reusing_identity() {
        let (mut io, _, consumer, registration) = fixture();
        let baseline = io.device_reference_count(registration.device_id());
        let mut catalog = BusInterfaceCatalog::new();
        let refused = catalog.prepare(&mut io, consumer, registration,
            BusInterfaceQueryRequest::standard()).unwrap();
        catalog.abort(&mut io, refused).unwrap();
        assert_eq!(catalog.active_count(), 0);
        assert_eq!(io.device_reference_count(registration.device_id()), baseline);
        let next = catalog.prepare(&mut io, consumer, registration,
            BusInterfaceQueryRequest::standard()).unwrap();
        assert_ne!(next.id(), refused.id());
        assert_eq!(catalog.commit(&io, refused), Err(NtStatus::INVALID_PARAMETER));
        catalog.abort(&mut io, next).unwrap();
    }

    #[test]
    fn uncertain_query_retains_pin_and_never_replays_or_commits() {
        let (mut io, _, consumer, registration) = fixture();
        let baseline = io.device_reference_count(registration.device_id());
        let mut catalog = BusInterfaceCatalog::new();
        let prepared = catalog.prepare(&mut io, consumer, registration,
            BusInterfaceQueryRequest::standard()).unwrap();
        catalog.retain_uncertain(prepared).unwrap();
        assert_eq!(catalog.commit(&io, prepared), Err(NtStatus::DEVICE_BUSY));
        assert_eq!(catalog.abort(&mut io, prepared), Err(NtStatus::DEVICE_BUSY));
        assert_eq!(catalog.prepared_provider(&io, prepared), Err(NtStatus::DEVICE_BUSY));
        assert_eq!(catalog.reference(&io, consumer, prepared.id(), |_| {
            panic!("uncertain query replayed")
        }), Err(NtStatus::DEVICE_BUSY));
        assert_eq!(catalog.active_count(), 1);
        assert_eq!(io.device_reference_count(registration.device_id()), baseline + 1);
        assert_eq!(io.retire_hosted_device_pointer(registration), Err(NtStatus::DEVICE_BUSY));
    }

    #[test]
    fn retains_exact_provider_and_clears_only_after_dereference() {
        let (mut io, _provider, consumer, registration) = fixture();
        let baseline = io.device_reference_count(registration.device_id());
        let mut catalog = BusInterfaceCatalog::new();
        let reply = successful_query(&mut catalog, &mut io, consumer, registration);
        assert_eq!(io.device_reference_count(registration.device_id()), baseline + 1);
        assert_eq!(catalog.device(&io, consumer, reply.lease_id), Ok(registration.device_id()));
        assert!(!reply.encode().windows(8).any(|bytes| bytes == 0x1000u64.to_le_bytes()));
        catalog.reference(&io, consumer, reply.lease_id, |provider| {
            assert_eq!(provider, registration); Ok(())
        }).unwrap();
        catalog.dereference(&mut io, consumer, reply.lease_id, |_| Ok(())).unwrap();
        assert_eq!(catalog.active_count(), 1);
        catalog.dereference(&mut io, consumer, reply.lease_id, |_| Ok(())).unwrap();
        assert_eq!(catalog.active_count(), 0);
        assert_eq!(io.device_reference_count(registration.device_id()), baseline);
    }

    #[test]
    fn rejects_other_consumer_and_stale_provider_generation() {
        let (mut io, provider, consumer, registration) = fixture();
        let other = io.register_hosted_domain();
        let mut catalog = BusInterfaceCatalog::new();
        let reply = successful_query(&mut catalog, &mut io, consumer, registration);
        assert_eq!(catalog.provider(&io, other, reply.lease_id), Err(NtStatus::ACCESS_DENIED));
        assert_eq!(catalog.provider(&io, provider, reply.lease_id), Err(NtStatus::ACCESS_DENIED));
        assert_eq!(io.retire_hosted_device_pointer(registration), Err(NtStatus::DEVICE_BUSY));
        catalog.dereference(&mut io, consumer, reply.lease_id, |_| Ok(())).unwrap();
        io.retire_hosted_device_pointer(registration).unwrap();
        assert_eq!(catalog.provider(&io, consumer, reply.lease_id), Err(NtStatus::INVALID_PARAMETER));
        let replacement = io.bind_hosted_device_pointer(
            provider, 0x1000, registration.device_id(),
        ).unwrap();
        assert_ne!(replacement, registration);
        let fresh = successful_query(&mut catalog, &mut io, consumer, replacement);
        assert_ne!(fresh.lease_id, reply.lease_id);
        assert_eq!(catalog.provider(&io, consumer, reply.lease_id), Err(NtStatus::INVALID_PARAMETER));
    }

    #[test]
    fn uncertain_reference_and_dereference_never_release_or_replay() {
        let (mut io, _, consumer, registration) = fixture();
        let mut catalog = BusInterfaceCatalog::new();
        let reply = successful_query(&mut catalog, &mut io, consumer, registration);
        let failure = NtStatus::DEVICE_NOT_CONNECTED;
        assert_eq!(catalog.reference(&io, consumer, reply.lease_id, |_| Err(failure)), Err(failure));
        assert_eq!(catalog.dereference(&mut io, consumer, reply.lease_id, |_| {
            panic!("uncertain provider callback replayed")
        }), Err(NtStatus::DEVICE_BUSY));
        assert_eq!(catalog.active_count(), 1);
        assert_eq!(catalog.provider(&io, consumer, reply.lease_id), Err(NtStatus::DEVICE_BUSY));
        let second = successful_query(&mut catalog, &mut io, consumer, registration);
        assert_eq!(catalog.dereference(&mut io, consumer, second.lease_id, |_| Err(failure)), Err(failure));
        assert_eq!(catalog.dereference(&mut io, consumer, second.lease_id, |_| {
            panic!("uncertain provider callback replayed")
        }), Err(NtStatus::DEVICE_BUSY));
        assert_eq!(catalog.active_count(), 2);
    }

    #[test]
    fn executive_pci_lease_has_its_own_reference_lifetime() {
        let (mut io, _, consumer, registration) = fixture();
        let baseline = io.device_reference_count(registration.device_id());
        let mut catalog = BusInterfaceCatalog::new();
        let reply = catalog.issue_executive_pci(&mut io, consumer, registration,
            BusInterfaceQueryRequest::standard()).unwrap();
        assert_eq!(io.device_reference_count(registration.device_id()), baseline + 1);
        assert_eq!(catalog.provider(&io, consumer, reply.lease_id), Ok(registration));
        assert_eq!(catalog.reference(&io, consumer, reply.lease_id, |_| {
            panic!("executive lease entered native provider")
        }), Err(NtStatus::INVALID_DEVICE_REQUEST));
        catalog.reference_executive_pci(&io, consumer, reply.lease_id).unwrap();
        catalog.dereference_executive_pci(&mut io, consumer, reply.lease_id).unwrap();
        assert_eq!(catalog.active_count(), 1);
        catalog.dereference_executive_pci(&mut io, consumer, reply.lease_id).unwrap();
        assert_eq!(catalog.active_count(), 0);
        assert_eq!(io.device_reference_count(registration.device_id()), baseline);
        assert_eq!(catalog.reference_executive_pci(&io, consumer, reply.lease_id),
            Err(NtStatus::INVALID_PARAMETER));
    }

    #[test]
    fn executive_pci_lease_cannot_be_reused_for_a_rebound_provider() {
        let (mut io, provider, consumer, registration) = fixture();
        let other = io.register_hosted_domain();
        let mut catalog = BusInterfaceCatalog::new();
        let first = catalog.issue_executive_pci(&mut io, consumer, registration,
            BusInterfaceQueryRequest::standard()).unwrap();
        assert_eq!(catalog.provider(&io, other, first.lease_id), Err(NtStatus::ACCESS_DENIED));
        assert_eq!(io.retire_hosted_device_pointer(registration), Err(NtStatus::DEVICE_BUSY));
        catalog.dereference_executive_pci(&mut io, consumer, first.lease_id).unwrap();
        io.retire_hosted_device_pointer(registration).unwrap();
        let rebound = io.bind_hosted_device_pointer(provider, 0x1000,
            registration.device_id()).unwrap();
        assert_ne!(rebound, registration);
        let second = catalog.issue_executive_pci(&mut io, consumer, rebound,
            BusInterfaceQueryRequest::standard()).unwrap();
        assert_ne!(first.lease_id, second.lease_id);
        assert_eq!(catalog.provider(&io, consumer, first.lease_id), Err(NtStatus::INVALID_PARAMETER));
        catalog.dereference_executive_pci(&mut io, consumer, second.lease_id).unwrap();
    }
}
