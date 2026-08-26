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

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedDomainIdentity {
    pub domain_id: HostedDomainId,
    pub cookie: u64,
}

impl Default for HostedDomainIdentity {
    fn default() -> Self {
        Self {
            domain_id: HostedDomainId::NULL,
            cookie: 0,
        }
    }
}

pub type HostedProviderIdentity = HostedDomainIdentity;

/// Canonical bindings owned by one isolated hosted-driver address space.
#[derive(Clone, Debug)]
pub struct HostedDomainRecord {
    cookie: u64,
    provider: Option<HostedDomainIdentity>,
    drivers: Vec<HostedPointerBinding<DriverId>>,
    devices: Vec<HostedPointerBinding<DeviceId>>,
    files: Vec<HostedPointerBinding<FileId>>,
}

impl HostedDomainRecord {
    fn new() -> Self {
        Self {
            cookie: 0,
            provider: None,
            drivers: Vec::new(),
            devices: Vec::new(),
            files: Vec::new(),
        }
    }

    pub fn cookie(&self) -> u64 {
        self.cookie
    }

    pub fn provider_identity(&self) -> Option<HostedDomainIdentity> {
        self.provider
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
) -> Result<(bool, bool), NtStatus> {
    if address == 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    if let Some(existing) = bindings
        .iter()
        .find(|binding| binding.address == address || binding.id == id)
    {
        return if existing.address == address && existing.id == id {
            Ok((false, false))
        } else {
            Err(NtStatus::OBJECT_NAME_COLLISION)
        };
    }
    let capacity = bindings.capacity();
    bindings
        .try_reserve(1)
        .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
    bindings.push(HostedPointerBinding { address, id });
    Ok((true, bindings.capacity() != capacity))
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

fn unbind<I: Copy + Eq>(bindings: &mut Vec<HostedPointerBinding<I>>, address: u64, id: I) -> bool {
    let Some(index) = bindings
        .iter()
        .position(|binding| binding.address == address && binding.id == id)
    else {
        return false;
    };
    bindings.swap_remove(index);
    true
}

impl<P> IoManager<P> {
    /// Allocate a fresh hosted address-domain identity. Its cookie is the same generation-protected
    /// value carried independently in authenticated dispatch envelopes.
    pub fn register_hosted_domain(&mut self) -> HostedDomainIdentity {
        let capacity = self.hosted_domains.capacity();
        let id = self
            .hosted_domains
            .insert_tagged(HostedDomainRecord::new(), self.durable_record_epoch);
        let record = self
            .hosted_domains
            .get_mut(id)
            .expect("just inserted domain");
        record.cookie = id.raw();
        let cookie = record.cookie;
        if self.hosted_domains.capacity() != capacity {
            self.mark_durable_storage_dirty();
        }
        self.note_durable_record_acquired();
        HostedDomainIdentity {
            domain_id: id,
            cookie,
        }
    }

    /// Remove one exact, empty hosted domain. Reuse of its slot receives a new generation and
    /// cookie. Pointer projections and provider links are leases and must be released first.
    pub fn unregister_hosted_domain(
        &mut self,
        identity: HostedDomainIdentity,
    ) -> Result<(), NtStatus> {
        let record = self
            .hosted_domains
            .get(identity.domain_id)
            .filter(|record| identity.cookie != 0 && record.cookie == identity.cookie)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let has_inbound_provider_link = self
            .hosted_domains
            .iter()
            .any(|(_, dependent)| dependent.provider == Some(identity));
        if !record.drivers.is_empty()
            || !record.devices.is_empty()
            || !record.files.is_empty()
            || record.provider.is_some()
            || has_inbound_provider_link
        {
            return Err(NtStatus::DEVICE_BUSY);
        }
        let (_, insertion_epoch) = self
            .hosted_domains
            .remove_tagged(identity.domain_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        self.note_durable_record_released(insertion_epoch);
        Ok(())
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

    /// Route a dependent domain through one exact live provider domain. Returns `true` only when
    /// this call created the lease; an identical replay returns `false`.
    pub fn set_hosted_domain_provider(
        &mut self,
        dependent: HostedDomainIdentity,
        provider: HostedDomainIdentity,
    ) -> Result<bool, NtStatus> {
        if dependent == provider {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.hosted_domains
            .get(provider.domain_id)
            .filter(|record| provider.cookie != 0 && record.cookie == provider.cookie)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let dependent_record = self
            .hosted_domains
            .get_mut(dependent.domain_id)
            .filter(|record| dependent.cookie != 0 && record.cookie == dependent.cookie)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        match dependent_record.provider {
            None => {
                dependent_record.provider = Some(provider);
                Ok(true)
            }
            Some(existing) if existing == provider => Ok(false),
            Some(_) => Err(NtStatus::OBJECT_NAME_COLLISION),
        }
    }

    /// Resolve the exact provider domain and generation cookie for a dependent domain.
    pub fn hosted_provider_identity(
        &self,
        dependent: HostedDomainIdentity,
    ) -> Option<HostedProviderIdentity> {
        let dependent = self
            .hosted_domains
            .get(dependent.domain_id)
            .filter(|record| dependent.cookie != 0 && record.cookie == dependent.cookie)?;
        let provider = dependent.provider?;
        self.hosted_domains
            .get(provider.domain_id)
            .filter(|record| provider.cookie != 0 && record.cookie == provider.cookie)?;
        Some(provider)
    }

    /// Clear one exact provider link. A stale teardown cannot erase a replacement route.
    pub fn clear_hosted_domain_provider(
        &mut self,
        dependent: HostedDomainIdentity,
        provider: HostedDomainIdentity,
    ) -> Result<(), NtStatus> {
        let dependent_record = self
            .hosted_domains
            .get_mut(dependent.domain_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if dependent.cookie == 0
            || dependent_record.cookie != dependent.cookie
            || dependent_record.provider != Some(provider)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        dependent_record.provider = None;
        Ok(())
    }

    /// Refuse provider unload while any exact dependent-domain lease remains.
    pub fn can_unload_hosted_provider(
        &self,
        provider: HostedDomainIdentity,
    ) -> Result<(), NtStatus> {
        self.hosted_domains
            .get(provider.domain_id)
            .filter(|record| provider.cookie != 0 && record.cookie == provider.cookie)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if self
            .hosted_domains
            .iter()
            .any(|(_, dependent)| dependent.provider == Some(provider))
        {
            Err(NtStatus::DEVICE_BUSY)
        } else {
            Ok(())
        }
    }

    pub fn bind_hosted_driver_identity(
        &mut self,
        identity: HostedDomainIdentity,
        address: u64,
        driver: DriverId,
    ) -> Result<(), NtStatus> {
        if self.driver(driver).is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let domain = self
            .hosted_domains
            .get_mut(identity.domain_id)
            .filter(|domain| identity.cookie != 0 && domain.cookie == identity.cookie)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let (_, grew) = bind(&mut domain.drivers, address, driver)?;
        if grew {
            self.mark_durable_storage_dirty();
        }
        Ok(())
    }

    /// Bind a hosted DeviceObject projection only when both independently carried pieces of the
    /// address-space identity still name the live domain generation.
    pub fn bind_hosted_device_identity(
        &mut self,
        identity: HostedDomainIdentity,
        address: u64,
        device: DeviceId,
    ) -> Result<(), NtStatus> {
        if self.device(device).is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let domain = self
            .hosted_domains
            .get_mut(identity.domain_id)
            .filter(|domain| identity.cookie != 0 && domain.cookie == identity.cookie)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let (_, grew) = bind(&mut domain.devices, address, device)?;
        if grew {
            self.mark_durable_storage_dirty();
        }
        Ok(())
    }

    pub fn bind_hosted_file_identity(
        &mut self,
        identity: HostedDomainIdentity,
        address: u64,
        file: FileId,
    ) -> Result<(), NtStatus> {
        if self.file(file).is_none() {
            return Err(NtStatus::INVALID_HANDLE);
        }
        let domain = self
            .hosted_domains
            .get_mut(identity.domain_id)
            .filter(|domain| identity.cookie != 0 && domain.cookie == identity.cookie)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let (_, grew) = bind(&mut domain.files, address, file)?;
        if grew {
            self.mark_durable_storage_dirty();
        }
        Ok(())
    }

    /// Remove one exact hosted DriverObject projection. Stale teardown cannot erase a replacement
    /// binding that reuses either the address or canonical id.
    pub fn unbind_hosted_driver_identity(
        &mut self,
        identity: HostedDomainIdentity,
        address: u64,
        driver: DriverId,
    ) -> bool {
        let Some(domain) = self.hosted_domains.get_mut(identity.domain_id) else {
            return false;
        };
        if identity.cookie == 0 || domain.cookie != identity.cookie {
            return false;
        }
        unbind(&mut domain.drivers, address, driver)
    }

    /// Remove one hosted DeviceObject projection only from the exact live domain generation.
    pub fn unbind_hosted_device_identity(
        &mut self,
        identity: HostedDomainIdentity,
        address: u64,
        device: DeviceId,
    ) -> bool {
        let Some(domain) = self.hosted_domains.get_mut(identity.domain_id) else {
            return false;
        };
        if identity.cookie == 0 || domain.cookie != identity.cookie {
            return false;
        }
        unbind(&mut domain.devices, address, device)
    }

    /// Remove one exact hosted FileObject projection.
    pub fn unbind_hosted_file_identity(
        &mut self,
        identity: HostedDomainIdentity,
        address: u64,
        file: FileId,
    ) -> bool {
        let Some(domain) = self.hosted_domains.get_mut(identity.domain_id) else {
            return false;
        };
        if identity.cookie == 0 || domain.cookie != identity.cookie {
            return false;
        }
        unbind(&mut domain.files, address, file)
    }

    pub fn hosted_driver_by_identity(
        &self,
        identity: HostedDomainIdentity,
        address: u64,
    ) -> Option<DriverId> {
        let record = self.hosted_domains.get(identity.domain_id)?;
        if identity.cookie == 0 || record.cookie != identity.cookie {
            return None;
        }
        let id = resolve(&record.drivers, address)?;
        self.driver(id).map(|_| id)
    }

    /// Resolve a hosted DeviceObject projection only when the generation-bearing domain id and
    /// the independently carried cookie both identify the current live address space.
    pub fn hosted_device_by_identity(
        &self,
        identity: HostedDomainIdentity,
        address: u64,
    ) -> Option<DeviceId> {
        let record = self.hosted_domains.get(identity.domain_id)?;
        if identity.cookie == 0 || record.cookie != identity.cookie {
            return None;
        }
        let id = resolve(&record.devices, address)?;
        self.device(id).map(|_| id)
    }

    pub fn hosted_file_by_identity(
        &self,
        identity: HostedDomainIdentity,
        address: u64,
    ) -> Option<FileId> {
        let record = self.hosted_domains.get(identity.domain_id)?;
        if identity.cookie == 0 || record.cookie != identity.cookie {
            return None;
        }
        let id = resolve(&record.files, address)?;
        self.file(id).map(|_| id)
    }

    pub fn hosted_driver_address_by_identity(
        &self,
        identity: HostedDomainIdentity,
        driver: DriverId,
    ) -> Option<u64> {
        self.driver(driver)?;
        let record = self.hosted_domains.get(identity.domain_id)?;
        if identity.cookie == 0 || record.cookie != identity.cookie {
            return None;
        }
        address_of(&record.drivers, driver)
    }

    /// Resolve the address of one canonical device only in the exact live domain generation.
    pub fn hosted_device_address_by_identity(
        &self,
        identity: HostedDomainIdentity,
        device: DeviceId,
    ) -> Option<u64> {
        self.device(device)?;
        let record = self.hosted_domains.get(identity.domain_id)?;
        if identity.cookie == 0 || record.cookie != identity.cookie {
            return None;
        }
        address_of(&record.devices, device)
    }

    pub fn hosted_file_address_by_identity(
        &self,
        identity: HostedDomainIdentity,
        file: FileId,
    ) -> Option<u64> {
        self.file(file)?;
        let record = self.hosted_domains.get(identity.domain_id)?;
        if identity.cookie == 0 || record.cookie != identity.cookie {
            return None;
        }
        address_of(&record.files, file)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::boxed::Box;

    use nt_status::NtStatus;
    use nt_types::{AccessMask, NtPath};

    use crate::{
        CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, HostedDomainIdentity,
        IoManager, MockDriverBackend, MockObjectPort, ShareAccess,
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
        let first_identity = io.register_hosted_domain();
        let second_identity = io.register_hosted_domain();
        let shared_address = 0x1000_0080;
        io.bind_hosted_driver_identity(first_identity, shared_address, first_driver)
            .unwrap();
        io.bind_hosted_driver_identity(second_identity, shared_address, second_driver)
            .unwrap();
        io.bind_hosted_device_identity(first_identity, shared_address + 8, first_device)
            .unwrap();
        io.bind_hosted_device_identity(second_identity, shared_address + 8, second_device)
            .unwrap();

        assert_eq!(
            io.hosted_driver_by_identity(first_identity, shared_address),
            Some(first_driver)
        );
        assert_eq!(
            io.hosted_driver_by_identity(second_identity, shared_address),
            Some(second_driver)
        );
        assert_eq!(
            io.hosted_device_by_identity(first_identity, shared_address + 8),
            Some(first_device)
        );
        assert_eq!(
            io.hosted_device_by_identity(second_identity, shared_address + 8),
            Some(second_device)
        );
        assert_eq!(
            io.hosted_device_by_identity(first_identity, shared_address + 8),
            Some(first_device)
        );
        assert_eq!(
            io.hosted_device_by_identity(
                HostedDomainIdentity {
                    cookie: first_identity.cookie.wrapping_add(1),
                    ..first_identity
                },
                shared_address + 8,
            ),
            None
        );
        assert_eq!(
            io.hosted_device_by_identity(
                HostedDomainIdentity {
                    cookie: 0,
                    ..first_identity
                },
                shared_address + 8,
            ),
            None
        );

        let stale = first_identity;
        let stale_cookie = stale.cookie;
        assert_eq!(
            io.unregister_hosted_domain(stale),
            Err(NtStatus::DEVICE_BUSY)
        );
        assert!(io.unbind_hosted_driver_identity(stale, shared_address, first_driver));
        assert!(io.unbind_hosted_device_identity(stale, shared_address + 8, first_device));
        assert_eq!(io.unregister_hosted_domain(stale), Ok(()));
        assert_eq!(io.hosted_driver_by_identity(stale, shared_address), None);
        assert_eq!(
            io.hosted_device_by_identity(first_identity, shared_address + 8),
            None
        );
        let replacement = io.register_hosted_domain();
        assert_eq!(replacement.domain_id.slot(), stale.domain_id.slot());
        assert_ne!(
            replacement.domain_id.generation(),
            stale.domain_id.generation()
        );
        assert_ne!(replacement.cookie, stale_cookie);
        assert_eq!(
            io.unregister_hosted_domain(stale),
            Err(NtStatus::INVALID_PARAMETER)
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
        let dependent_identity = io.register_hosted_domain();
        let provider_identity = io.register_hosted_domain();

        assert_eq!(io.hosted_provider_identity(dependent_identity), None);
        assert_eq!(
            io.set_hosted_domain_provider(
                dependent_identity,
                HostedDomainIdentity {
                    cookie: 0,
                    ..provider_identity
                }
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            io.set_hosted_domain_provider(
                dependent_identity,
                HostedDomainIdentity {
                    cookie: provider_identity.cookie.wrapping_add(1),
                    ..provider_identity
                }
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );

        assert_eq!(
            io.bind_hosted_driver_identity(dependent_identity, 0x2000, driver),
            Ok(())
        );
        assert_eq!(
            io.bind_hosted_driver_identity(dependent_identity, 0x2000, other_driver),
            Err(NtStatus::OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            io.bind_hosted_driver_identity(dependent_identity, 0x3000, driver),
            Err(NtStatus::OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            io.bind_hosted_device_identity(dependent_identity, 0x4000, device),
            Ok(())
        );
        assert_eq!(
            io.bind_hosted_file_identity(dependent_identity, 0x5000, file),
            Ok(())
        );
        assert_eq!(
            io.hosted_file_by_identity(dependent_identity, 0x5000),
            Some(file)
        );

        assert!(!io.unbind_hosted_driver_identity(dependent_identity, 0x2000, other_driver));
        assert_eq!(
            io.hosted_driver_by_identity(dependent_identity, 0x2000),
            Some(driver)
        );
        assert!(io.unbind_hosted_driver_identity(dependent_identity, 0x2000, driver));
        assert_eq!(
            io.hosted_driver_by_identity(dependent_identity, 0x2000),
            None
        );
        assert_eq!(
            io.bind_hosted_driver_identity(dependent_identity, 0x2000, other_driver),
            Ok(())
        );

        let stale_cookie = HostedDomainIdentity {
            cookie: dependent_identity.cookie.wrapping_add(1),
            ..dependent_identity
        };
        assert_eq!(
            io.bind_hosted_device_identity(stale_cookie, 0x4008, device),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert!(!io.unbind_hosted_device_identity(stale_cookie, 0x4000, device));
        assert_eq!(
            io.hosted_device_by_identity(dependent_identity, 0x4000),
            Some(device)
        );
        assert_eq!(
            io.hosted_device_address_by_identity(dependent_identity, device),
            Some(0x4000)
        );
        assert_eq!(
            io.hosted_device_address_by_identity(stale_cookie, device),
            None
        );
        assert!(!io.unbind_hosted_device_identity(dependent_identity, 0x4008, device));
        assert!(io.unbind_hosted_device_identity(dependent_identity, 0x4000, device));
        assert_eq!(
            io.hosted_device_by_identity(dependent_identity, 0x4000),
            None
        );
        assert_eq!(
            io.bind_hosted_device_identity(dependent_identity, 0x4008, device),
            Ok(())
        );

        assert!(!io.unbind_hosted_file_identity(dependent_identity, 0x5008, file));
        assert!(io.unbind_hosted_file_identity(dependent_identity, 0x5000, file));
        assert_eq!(io.hosted_file_by_identity(dependent_identity, 0x5000), None);
        assert_eq!(
            io.bind_hosted_file_identity(dependent_identity, 0x5008, file),
            Ok(())
        );

        assert_eq!(
            io.set_hosted_domain_provider(dependent_identity, provider_identity),
            Ok(true)
        );
        assert_eq!(
            io.set_hosted_domain_provider(dependent_identity, provider_identity),
            Ok(false)
        );
        assert_eq!(
            io.hosted_provider_identity(dependent_identity),
            Some(provider_identity)
        );
        assert_eq!(
            io.clear_hosted_domain_provider(
                dependent_identity,
                HostedDomainIdentity {
                    cookie: provider_identity.cookie.wrapping_add(1),
                    ..provider_identity
                }
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            io.hosted_provider_identity(dependent_identity),
            Some(provider_identity)
        );
        assert_eq!(
            io.can_unload_hosted_provider(provider_identity),
            Err(NtStatus::DEVICE_BUSY)
        );
        assert_eq!(
            io.unregister_hosted_domain(provider_identity),
            Err(NtStatus::DEVICE_BUSY)
        );
        io.clear_hosted_domain_provider(dependent_identity, provider_identity)
            .unwrap();
        assert_eq!(io.hosted_provider_identity(dependent_identity), None);
        assert_eq!(io.can_unload_hosted_provider(provider_identity), Ok(()));
        assert_eq!(io.unregister_hosted_domain(provider_identity), Ok(()));
        assert_eq!(
            io.set_hosted_domain_provider(dependent_identity, provider_identity),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }
}
