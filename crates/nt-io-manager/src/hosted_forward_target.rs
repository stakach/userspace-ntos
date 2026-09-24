//! Exact consumer-side device authority for a forwarded hosted IRP.

use crate::{
    DeviceId, DeviceReference, HostedDevicePointerRegistration, HostedDomainIdentity, IoManager,
};
use nt_status::NtStatus;

#[derive(Debug)]
#[must_use = "release the retained target device after forwarding retires"]
pub struct HostedForwardTarget {
    registration: HostedDevicePointerRegistration,
    reference: DeviceReference,
}

impl HostedForwardTarget {
    /// The address is meaningful only with the exact consumer domain and its live registration.
    pub fn capture<P>(
        io: &mut IoManager<P>,
        domain: HostedDomainIdentity,
        address: u64,
    ) -> Result<Self, NtStatus> {
        let registration = io
            .hosted_device_pointer_registration(domain, address)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let reference = io.retain_hosted_device_reference(domain, address)?;
        debug_assert_eq!(registration.device_id(), reference.device_id());
        Ok(Self {
            registration,
            reference,
        })
    }

    pub const fn device_id(&self) -> DeviceId {
        self.registration.device_id()
    }

    pub const fn registration(&self) -> HostedDevicePointerRegistration {
        self.registration
    }

    /// Recheck the generation-bearing binding before an irreversible provider dispatch.
    pub fn validate<P>(&self, io: &IoManager<P>) -> Result<DeviceId, NtStatus> {
        if !self.reference.is_held()
            || io.hosted_device_pointer_registration(
                self.registration.domain(),
                self.registration.address(),
            ) != Some(self.registration)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(self.registration.device_id())
    }

    /// A refused release keeps the exact owner available for redrive.
    pub fn release<P>(&mut self, io: &mut IoManager<P>) -> Result<(), NtStatus> {
        io.release_device_reference(&mut self.reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceCharacteristics, DeviceFlags, DeviceType, MockDriverBackend, MockObjectPort,
    };
    use alloc::boxed::Box;
    use nt_types::NtPath;

    fn fixture() -> (IoManager<MockObjectPort>, HostedDomainIdentity, DeviceId) {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\ForwardTarget").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let device = io
            .create_device(
                driver,
                Some(&NtPath::parse_str(r"\Device\ForwardTarget").unwrap()),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let consumer = io.register_hosted_domain();
        (io, consumer, device)
    }

    #[test]
    fn requires_registered_consumer_projection_and_retains_exact_device() {
        let (mut io, consumer, device) = fixture();
        assert!(HostedForwardTarget::capture(&mut io, consumer, 0x5000).is_err());
        let registration = io.bind_hosted_device_pointer(consumer, 0x5000, device).unwrap();
        let baseline = io.device_reference_count(device);
        let mut target = HostedForwardTarget::capture(&mut io, consumer, 0x5000).unwrap();
        assert_eq!(target.device_id(), device);
        assert_eq!(target.registration(), registration);
        assert_eq!(target.validate(&io), Ok(device));
        assert_eq!(io.device_reference_count(device), baseline + 1);
        target.release(&mut io).unwrap();
        assert!(target.validate(&io).is_err());
        assert_eq!(io.device_reference_count(device), baseline);
    }

    #[test]
    fn same_numeric_address_in_another_domain_is_not_authority() {
        let (mut io, consumer, device) = fixture();
        io.bind_hosted_device_pointer(consumer, 0x5000, device).unwrap();
        let other = io.register_hosted_domain();
        assert!(HostedForwardTarget::capture(&mut io, other, 0x5000).is_err());
        let stale = HostedDomainIdentity {
            cookie: consumer.cookie.wrapping_add(1),
            ..consumer
        };
        assert!(HostedForwardTarget::capture(&mut io, stale, 0x5000).is_err());
    }
}
