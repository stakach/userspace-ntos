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
    uncertain: bool,
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

    /// Take one independent canonical reference after the provider's successful QueryInterface
    /// has acquired its initial native interface reference.
    pub fn issue<P>(
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
            target.release(io).expect("captured stale bus provider");
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let id = self.next_id;
        self.leases.push(Lease {
            id,
            consumer,
            provider,
            target,
            references: 1,
            uncertain: false,
        });
        self.next_id = next;
        Ok(BusInterfaceQueryReply {
            size: BUS_INTERFACE_STANDARD_X64_SIZE,
            version: 1,
            lease_id: id,
            device_id: provider.device_id().raw(),
        })
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
        if lease.uncertain {
            return Err(NtStatus::DEVICE_BUSY);
        }
        lease.references = lease.references.checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        let result = invoke(lease.provider);
        if result.is_err() {
            lease.uncertain = true;
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
        if self.leases[index].uncertain {
            return Err(NtStatus::DEVICE_BUSY);
        }
        let provider = self.leases[index].provider;
        if let Err(status) = invoke(provider) {
            self.leases[index].uncertain = true;
            return Err(status);
        }
        if self.leases[index].references > 1 {
            self.leases[index].references -= 1;
            return Ok(());
        }
        if let Err(status) = self.leases[index].target.release(io) {
            self.leases[index].uncertain = true;
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

    #[test]
    fn retains_exact_provider_and_clears_only_after_dereference() {
        let (mut io, _provider, consumer, registration) = fixture();
        let baseline = io.device_reference_count(registration.device_id());
        let mut catalog = BusInterfaceCatalog::new();
        let reply = catalog.issue(&mut io, consumer, registration,
            BusInterfaceQueryRequest::standard()).unwrap();
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
        let reply = catalog.issue(&mut io, consumer, registration,
            BusInterfaceQueryRequest::standard()).unwrap();
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
        let fresh = catalog.issue(&mut io, consumer, replacement,
            BusInterfaceQueryRequest::standard()).unwrap();
        assert_ne!(fresh.lease_id, reply.lease_id);
        assert_eq!(catalog.provider(&io, consumer, reply.lease_id), Err(NtStatus::INVALID_PARAMETER));
    }

    #[test]
    fn uncertain_reference_and_dereference_never_release_or_replay() {
        let (mut io, _, consumer, registration) = fixture();
        let mut catalog = BusInterfaceCatalog::new();
        let reply = catalog.issue(&mut io, consumer, registration,
            BusInterfaceQueryRequest::standard()).unwrap();
        let failure = NtStatus::DEVICE_NOT_CONNECTED;
        assert_eq!(catalog.reference(&io, consumer, reply.lease_id, |_| Err(failure)), Err(failure));
        assert_eq!(catalog.dereference(&mut io, consumer, reply.lease_id, |_| {
            panic!("uncertain provider callback replayed")
        }), Err(NtStatus::DEVICE_BUSY));
        assert_eq!(catalog.active_count(), 1);
        assert_eq!(catalog.provider(&io, consumer, reply.lease_id), Ok(registration));
        let second = catalog.issue(&mut io, consumer, registration,
            BusInterfaceQueryRequest::standard()).unwrap();
        assert_eq!(catalog.dereference(&mut io, consumer, second.lease_id, |_| Err(failure)), Err(failure));
        assert_eq!(catalog.dereference(&mut io, consumer, second.lease_id, |_| {
            panic!("uncertain provider callback replayed")
        }), Err(NtStatus::DEVICE_BUSY));
        assert_eq!(catalog.active_count(), 2);
    }
}
