//! Domain-scoped identities for hosted WDM compatibility pointers.
//!
//! A WDM pointer is meaningful only in the isolated component that owns its address space. This
//! registry binds `(HostedDomainId, address)` to canonical I/O Manager ids and rejects ambiguous or
//! stale identities. Raw addresses never act as global routing keys.

use alloc::vec::Vec;

use nt_status::NtStatus;

use crate::{DeviceId, DriverId, FileId, HostedDomainId, IoManager};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostedPointerBinding<I> {
    address: u64,
    id: I,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedDomainIdentity {
    pub domain_id: HostedDomainId,
    pub cookie: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedProviderIdentity {
    pub domain_id: HostedDomainId,
    pub cookie: u64,
}

/// Canonical bindings owned by one isolated hosted-driver address space.
#[derive(Clone, Debug)]
pub struct HostedDomainRecord {
    cookie: u64,
    provider_domain_id: HostedDomainId,
    provider_cookie: u64,
    drivers: Vec<HostedPointerBinding<DriverId>>,
    devices: Vec<HostedPointerBinding<DeviceId>>,
    files: Vec<HostedPointerBinding<FileId>>,
}

impl HostedDomainRecord {
    fn new() -> Self {
        Self {
            cookie: 0,
            provider_domain_id: HostedDomainId::NULL,
            provider_cookie: 0,
            drivers: Vec::new(),
            devices: Vec::new(),
            files: Vec::new(),
        }
    }

    pub fn cookie(&self) -> u64 {
        self.cookie
    }

    pub fn provider_domain_id(&self) -> HostedDomainId {
        self.provider_domain_id
    }

    pub fn provider_cookie(&self) -> u64 {
        self.provider_cookie
    }

    pub fn driver_binding_count(&self) -> usize {
        self.drivers.len()
    }

    pub fn device_binding_count(&self) -> usize {
        self.devices.len()
    }

    pub fn file_binding_count(&self) -> usize {
        self.files.len()
    }
}

fn bind<I: Copy + Eq>(
    bindings: &mut Vec<HostedPointerBinding<I>>,
    address: u64,
    id: I,
) -> Result<(), NtStatus> {
    if address == 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    if let Some(existing) = bindings
        .iter()
        .find(|binding| binding.address == address || binding.id == id)
    {
        return if existing.address == address && existing.id == id {
            Ok(())
        } else {
            Err(NtStatus::OBJECT_NAME_COLLISION)
        };
    }
    bindings
        .try_reserve(1)
        .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
    bindings.push(HostedPointerBinding { address, id });
    Ok(())
}

fn resolve<I: Copy + Eq>(bindings: &[HostedPointerBinding<I>], address: u64) -> Option<I> {
    if address == 0 {
        return None;
    }
    bindings
        .iter()
        .find(|binding| binding.address == address)
        .map(|binding| binding.id)
}

fn address_of<I: Copy + Eq>(bindings: &[HostedPointerBinding<I>], id: I) -> Option<u64> {
    bindings
        .iter()
        .find(|binding| binding.id == id)
        .map(|binding| binding.address)
}

impl<P> IoManager<P> {
    /// Allocate a fresh hosted address-domain identity. Its cookie is the same generation-protected
    /// value carried independently in authenticated dispatch envelopes.
    pub fn register_hosted_domain(&mut self) -> HostedDomainId {
        let id = self.hosted_domains.insert(HostedDomainRecord::new());
        let record = self
            .hosted_domains
            .get_mut(id)
            .expect("just inserted domain");
        record.cookie = id.raw();
        id
    }

    /// Remove a hosted domain. Reuse of its slot receives a new generation and cookie.
    pub fn unregister_hosted_domain(&mut self, domain: HostedDomainId) -> bool {
        self.hosted_domains.remove(domain).is_some()
    }

    pub fn hosted_domain(&self, domain: HostedDomainId) -> Option<&HostedDomainRecord> {
        self.hosted_domains.get(domain)
    }

    pub fn hosted_domain_identity(&self, domain: HostedDomainId) -> Option<HostedDomainIdentity> {
        let record = self.hosted_domains.get(domain)?;
        Some(HostedDomainIdentity {
            domain_id: domain,
            cookie: record.cookie,
        })
    }

    /// Route a dependent domain through one exact live provider domain.
    pub fn set_hosted_domain_provider(
        &mut self,
        domain: HostedDomainId,
        provider: HostedDomainId,
        provider_cookie: u64,
    ) -> Result<(), NtStatus> {
        if provider_cookie == 0 || self.hosted_domains.get(provider).is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let domain = self
            .hosted_domains
            .get_mut(domain)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        domain.provider_domain_id = provider;
        domain.provider_cookie = provider_cookie;
        Ok(())
    }

    /// Resolve the exact provider domain and generation cookie for a dependent domain.
    pub fn hosted_provider_identity(
        &self,
        domain: HostedDomainId,
    ) -> Option<HostedProviderIdentity> {
        let dependent = self.hosted_domains.get(domain)?;
        let provider_domain_id = dependent.provider_domain_id;
        if provider_domain_id == HostedDomainId::NULL || dependent.provider_cookie == 0 {
            return None;
        }
        self.hosted_domains.get(provider_domain_id)?;
        Some(HostedProviderIdentity {
            domain_id: provider_domain_id,
            cookie: dependent.provider_cookie,
        })
    }

    pub fn bind_hosted_driver_address(
        &mut self,
        domain: HostedDomainId,
        address: u64,
        driver: DriverId,
    ) -> Result<(), NtStatus> {
        if self.driver(driver).is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        bind(
            &mut self
                .hosted_domains
                .get_mut(domain)
                .ok_or(NtStatus::INVALID_PARAMETER)?
                .drivers,
            address,
            driver,
        )
    }

    pub fn bind_hosted_device_address(
        &mut self,
        domain: HostedDomainId,
        address: u64,
        device: DeviceId,
    ) -> Result<(), NtStatus> {
        if self.device(device).is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        bind(
            &mut self
                .hosted_domains
                .get_mut(domain)
                .ok_or(NtStatus::INVALID_PARAMETER)?
                .devices,
            address,
            device,
        )
    }

    pub fn bind_hosted_file_address(
        &mut self,
        domain: HostedDomainId,
        address: u64,
        file: FileId,
    ) -> Result<(), NtStatus> {
        if self.file(file).is_none() {
            return Err(NtStatus::INVALID_HANDLE);
        }
        bind(
            &mut self
                .hosted_domains
                .get_mut(domain)
                .ok_or(NtStatus::INVALID_PARAMETER)?
                .files,
            address,
            file,
        )
    }

    pub fn hosted_driver_by_address(
        &self,
        domain: HostedDomainId,
        address: u64,
    ) -> Option<DriverId> {
        let id = resolve(&self.hosted_domains.get(domain)?.drivers, address)?;
        self.driver(id).map(|_| id)
    }

    pub fn hosted_device_by_address(
        &self,
        domain: HostedDomainId,
        address: u64,
    ) -> Option<DeviceId> {
        let id = resolve(&self.hosted_domains.get(domain)?.devices, address)?;
        self.device(id).map(|_| id)
    }

    pub fn hosted_file_by_address(&self, domain: HostedDomainId, address: u64) -> Option<FileId> {
        let id = resolve(&self.hosted_domains.get(domain)?.files, address)?;
        self.file(id).map(|_| id)
    }

    pub fn hosted_driver_address(&self, domain: HostedDomainId, driver: DriverId) -> Option<u64> {
        self.driver(driver)?;
        address_of(&self.hosted_domains.get(domain)?.drivers, driver)
    }

    pub fn hosted_device_address(&self, domain: HostedDomainId, device: DeviceId) -> Option<u64> {
        self.device(device)?;
        address_of(&self.hosted_domains.get(domain)?.devices, device)
    }

    pub fn hosted_file_address(&self, domain: HostedDomainId, file: FileId) -> Option<u64> {
        self.file(file)?;
        address_of(&self.hosted_domains.get(domain)?.files, file)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::boxed::Box;

    use nt_status::NtStatus;
    use nt_types::{AccessMask, NtPath};

    use crate::{
        CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, IoManager,
        MockDriverBackend, MockObjectPort, ShareAccess,
    };

    fn path(value: &str) -> NtPath {
        NtPath::parse_str(value).unwrap()
    }

    #[test]
    fn identical_addresses_are_isolated_by_generation_protected_domain() {
        let mut io = IoManager::new(MockObjectPort::new());
        let first_driver = io
            .create_driver(
                &path("\\Driver\\FirstDomain"),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let second_driver = io
            .create_driver(
                &path("\\Driver\\SecondDomain"),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let first_device = io
            .create_device(
                first_driver,
                Some(&path("\\Device\\FirstDomain")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let second_device = io
            .create_device(
                second_driver,
                Some(&path("\\Device\\SecondDomain")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let first = io.register_hosted_domain();
        let second = io.register_hosted_domain();
        let shared_address = 0x1000_0080;
        io.bind_hosted_driver_address(first, shared_address, first_driver)
            .unwrap();
        io.bind_hosted_driver_address(second, shared_address, second_driver)
            .unwrap();
        io.bind_hosted_device_address(first, shared_address + 8, first_device)
            .unwrap();
        io.bind_hosted_device_address(second, shared_address + 8, second_device)
            .unwrap();

        assert_eq!(
            io.hosted_driver_by_address(first, shared_address),
            Some(first_driver)
        );
        assert_eq!(
            io.hosted_driver_by_address(second, shared_address),
            Some(second_driver)
        );
        assert_eq!(
            io.hosted_device_by_address(first, shared_address + 8),
            Some(first_device)
        );
        assert_eq!(
            io.hosted_device_by_address(second, shared_address + 8),
            Some(second_device)
        );

        let stale = first;
        let stale_cookie = io.hosted_domain(stale).unwrap().cookie();
        assert!(io.unregister_hosted_domain(stale));
        assert_eq!(io.hosted_driver_by_address(stale, shared_address), None);
        let replacement = io.register_hosted_domain();
        assert_eq!(replacement.slot(), stale.slot());
        assert_ne!(replacement.generation(), stale.generation());
        assert_ne!(
            io.hosted_domain(replacement).unwrap().cookie(),
            stale_cookie
        );
    }

    #[test]
    fn bindings_are_one_to_one_and_provider_links_fail_closed() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io
            .create_driver(
                &path("\\Driver\\Domain"),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let other_driver = io
            .create_driver(
                &path("\\Driver\\OtherDomain"),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let device = io
            .create_device(
                driver,
                Some(&path("\\Device\\Domain")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let client = io.register_client();
        let handle = io
            .open(
                client,
                &path("\\Device\\Domain"),
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                1,
            )
            .unwrap();
        let file = io
            .reference_open_file(client, handle, AccessMask::empty())
            .unwrap()
            .0;
        let dependent = io.register_hosted_domain();
        let provider = io.register_hosted_domain();

        assert_eq!(io.hosted_provider_identity(dependent), None);
        assert_eq!(
            io.set_hosted_domain_provider(dependent, provider, 0),
            Err(NtStatus::INVALID_PARAMETER)
        );

        assert_eq!(
            io.bind_hosted_driver_address(dependent, 0x2000, driver),
            Ok(())
        );
        assert_eq!(
            io.bind_hosted_driver_address(dependent, 0x2000, other_driver),
            Err(NtStatus::OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            io.bind_hosted_driver_address(dependent, 0x3000, driver),
            Err(NtStatus::OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            io.bind_hosted_device_address(dependent, 0x4000, device),
            Ok(())
        );
        assert_eq!(io.bind_hosted_file_address(dependent, 0x5000, file), Ok(()));
        assert_eq!(io.hosted_file_by_address(dependent, 0x5000), Some(file));

        io.set_hosted_domain_provider(dependent, provider, 0x55aa)
            .unwrap();
        let identity = io.hosted_provider_identity(dependent).unwrap();
        assert_eq!(identity.domain_id, provider);
        assert_eq!(identity.cookie, 0x55aa);
        assert!(io.unregister_hosted_domain(provider));
        assert_eq!(io.hosted_provider_identity(dependent), None);
        assert_eq!(
            io.set_hosted_domain_provider(dependent, provider, 0x55aa),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }
}
