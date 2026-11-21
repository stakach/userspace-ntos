//! Source-IRP geometry shared by every cross-domain IRP forward.
//!
//! A hosted driver's `IofCallDriver` names its target in the IRP's next stack location. The
//! component addresses here are lookup keys inside the source domain's registered packet,
//! never authority of their own.

use nt_kernel_abi::{IoStackLocation, Irp};
use nt_status::NtStatus;

use crate::source_irp_ledger::{SourceIrpAllocation, SourceIrpLedger};
use crate::{DeviceId, HostedDevicePointerRegistration, HostedDomainIdentity, IoManager};

/// `IO_TYPE_IRP`.
const IO_TYPE_IRP: i16 = 6;
const IRP_BYTES: u64 = core::mem::size_of::<Irp>() as u64;
const STACK_LOCATION_BYTES: u64 = core::mem::size_of::<IoStackLocation>() as u64;

/// The component address of the next stack location of a source IRP registered as
/// `allocation`: the location an `IofCallDriver` caller fills for its target. `None` unless
/// the packet header is the registered packet with a current location that has a next one.
pub fn next_stack_location(allocation: SourceIrpAllocation, irp: &Irp) -> Option<u64> {
    if irp.type_ != IO_TYPE_IRP || irp.size as u64 != allocation.bytes {
        return None;
    }
    let location = u8::try_from(irp.current_location).ok()?;
    if location < 2
        || location > allocation.stack_count.saturating_add(1)
        || irp.stack_count != allocation.stack_count as i8
    {
        return None;
    }
    let stack_base = allocation.component_address + IRP_BYTES;
    let current_stack = stack_base + (location as u64 - 1) * STACK_LOCATION_BYTES;
    if irp.current_stack_location.0 != current_stack {
        return None;
    }
    Some(current_stack - STACK_LOCATION_BYTES)
}

/// Reads of a source domain's registered packet memory, by component address.
pub trait SourcePacketMemory {
    fn irp(&self, address: u64) -> Option<Irp>;
    fn stack_location(&self, address: u64) -> Option<IoStackLocation>;
}

/// Why the root refused a hosted driver's lane `IofCallDriver` before any target dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallDriverRefusal {
    /// The packet is not a live source IRP owned by the calling instance.
    ForeignIrp,
    /// The DEVICE_OBJECT has no registration in the source domain, or no instance dispatches it.
    ForeignDevice,
    /// The IRP has no next stack location, or it does not name the target device.
    StackMismatch,
    /// The target is dispatched in the source's own domain, which calls it locally.
    LocalTarget,
}

impl CallDriverRefusal {
    /// The statuses the primary forward captures return for the same defects.
    pub const fn status(self) -> NtStatus {
        match self {
            Self::ForeignIrp => NtStatus::INVALID_HANDLE,
            Self::ForeignDevice | Self::LocalTarget => NtStatus::INVALID_DEVICE_REQUEST,
            Self::StackMismatch => NtStatus::INVALID_PARAMETER,
        }
    }
}

/// A source IRP admitted for a cross-domain `IofCallDriver`. Observation only: it neither pins
/// the IRP nor references the target, and authorizes nothing after the ledger lock is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallDriverAdmission {
    pub allocation: SourceIrpAllocation,
    pub target: HostedDevicePointerRegistration,
    pub target_domain: HostedDomainIdentity,
    /// The next stack location's MajorFunction.
    pub major: u8,
}

/// Admit `IofCallDriver(device, irp)` from hosted instance `instance` of `source`.
///
/// The packet must be a live source IRP the instance may forward, `device` must be a registered
/// DEVICE_OBJECT pointer in the source domain, the next stack location must name it, and the
/// device's canonical registration must resolve (through `device_domain`) to another domain.
#[allow(clippy::too_many_arguments)]
pub fn admit_call_driver<P>(
    io: &IoManager<P>,
    ledger: &SourceIrpLedger,
    instance: usize,
    source: HostedDomainIdentity,
    irp: u64,
    device: u64,
    memory: &impl SourcePacketMemory,
    device_domain: impl FnOnce(DeviceId) -> Option<HostedDomainIdentity>,
) -> Result<CallDriverAdmission, CallDriverRefusal> {
    let (_, allocation) = ledger
        .hosted_forward_allocation(instance, source, irp)
        .map_err(|_| CallDriverRefusal::ForeignIrp)?;
    let target = io
        .hosted_device_pointer_registration(source, device)
        .ok_or(CallDriverRefusal::ForeignDevice)?;
    let next = memory
        .irp(irp)
        .and_then(|packet| next_stack_location(allocation, &packet))
        .and_then(|next| memory.stack_location(next))
        .ok_or(CallDriverRefusal::StackMismatch)?;
    if next.device_object.0 != device {
        return Err(CallDriverRefusal::StackMismatch);
    }
    let target_domain =
        device_domain(target.device_id()).ok_or(CallDriverRefusal::ForeignDevice)?;
    if target_domain == source {
        return Err(CallDriverRefusal::LocalTarget);
    }
    Ok(CallDriverAdmission { allocation, target, target_domain, major: next.major_function })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_irp_ledger::SourceIrpOwner;
    use crate::{HostedDomainId, HostedDomainIdentity};
    use nt_kernel_abi::GuestAddr;

    const PACKET: u64 = 0x9000;

    fn allocation(stack_count: u8) -> SourceIrpAllocation {
        SourceIrpAllocation {
            owner: SourceIrpOwner::HostedDriver(3),
            domain: HostedDomainIdentity { domain_id: HostedDomainId(7), cookie: 11 },
            component_address: PACKET,
            bytes: 208 + 72 * stack_count as u64,
            stack_count,
            pool_generation: 1,
        }
    }

    /// The header `IoAllocateIrp` writes, at current location `location`.
    fn packet(allocation: SourceIrpAllocation, location: i8) -> Irp {
        // SAFETY: `Irp` is a plain-old-data ABI record; all-zero is a valid value.
        let mut irp: Irp = unsafe { core::mem::zeroed() };
        irp.type_ = 6;
        irp.size = allocation.bytes as u16;
        irp.stack_count = allocation.stack_count as i8;
        irp.current_location = location;
        irp.current_stack_location =
            GuestAddr(PACKET + 208 + (location as u64).wrapping_sub(1) * 72);
        irp
    }

    #[test]
    fn next_location_is_the_one_below_the_current_location() {
        let registered = allocation(3);
        // A fresh packet sits at StackCount + 1; its first IofCallDriver fills location 3.
        assert_eq!(next_stack_location(registered, &packet(registered, 4)),
            Some(PACKET + 208 + 2 * 72));
        assert_eq!(next_stack_location(registered, &packet(registered, 2)), Some(PACKET + 208));
    }

    #[test]
    fn a_packet_with_no_next_location_or_a_foreign_header_has_none() {
        let registered = allocation(3);
        assert_eq!(next_stack_location(registered, &packet(registered, 1)), None,
            "the last location has no next one");
        assert_eq!(next_stack_location(registered, &packet(registered, 5)), None);
        let mut irp = packet(registered, 3);
        irp.type_ = 5;
        assert_eq!(next_stack_location(registered, &irp), None);
        let mut irp = packet(registered, 3);
        irp.size += 72;
        assert_eq!(next_stack_location(registered, &irp), None, "not the registered size");
        let mut irp = packet(registered, 3);
        irp.stack_count = 2;
        assert_eq!(next_stack_location(registered, &irp), None);
        let mut irp = packet(registered, 3);
        irp.current_stack_location.0 += 72;
        assert_eq!(next_stack_location(registered, &irp), None,
            "CurrentStackLocation must agree with CurrentLocation");
    }

    mod call_driver {
        use super::*;
        use crate::source_irp_ledger::SourceIrpLedger;
        use crate::{
            DeviceCharacteristics, DeviceFlags, DeviceId, DeviceType, IoManager,
            MockDriverBackend, MockObjectPort,
        };
        use alloc::boxed::Box;
        use nt_types::NtPath;

        const DEVICE: u64 = 0x5000;
        const SOURCE: usize = 3;

        /// The source packet as a hosted driver's IoAllocateIrp left it, with the next stack
        /// location naming `next_device`.
        struct Packet {
            address: u64,
            irp: Irp,
            next: IoStackLocation,
        }

        impl SourcePacketMemory for Packet {
            fn irp(&self, address: u64) -> Option<Irp> {
                (address == self.address).then_some(self.irp)
            }
            fn stack_location(&self, address: u64) -> Option<IoStackLocation> {
                (address == self.irp.current_stack_location.0 - 72).then_some(self.next)
            }
        }

        struct Fixture {
            io: IoManager<MockObjectPort>,
            ledger: SourceIrpLedger,
            source: HostedDomainIdentity,
            target: HostedDomainIdentity,
            device: DeviceId,
            allocation: SourceIrpAllocation,
        }

        fn fixture() -> Fixture {
            let mut io = IoManager::new(MockObjectPort::new());
            let driver = io.create_driver(
                &NtPath::parse_str(r"\Driver\CallDriverTarget").unwrap(),
                Box::new(MockDriverBackend::new()),
            ).unwrap();
            let device = io.create_device(
                driver, Some(&NtPath::parse_str(r"\Device\CallDriverTarget").unwrap()),
                DeviceType::UNKNOWN, DeviceCharacteristics::empty(), DeviceFlags::BUFFERED_IO, 0,
            ).unwrap();
            let source = io.register_hosted_domain();
            let target = io.register_hosted_domain();
            io.bind_hosted_device_pointer(source, DEVICE, device).unwrap();
            let allocation = SourceIrpAllocation {
                owner: SourceIrpOwner::HostedDriver(SOURCE),
                domain: source,
                ..super::allocation(2)
            };
            let mut ledger = SourceIrpLedger::new();
            ledger.register(allocation).unwrap();
            Fixture { io, ledger, source, target, device, allocation }
        }

        fn packet(allocation: SourceIrpAllocation, next_device: u64) -> Packet {
            // SAFETY: `IoStackLocation` is a plain-old-data ABI record; all-zero is valid.
            let mut next: IoStackLocation = unsafe { core::mem::zeroed() };
            next.major_function = 3;
            next.device_object = GuestAddr(next_device);
            let mut irp = super::packet(allocation, 3);
            irp.current_stack_location.0 += allocation.component_address - PACKET;
            Packet { address: allocation.component_address, irp, next }
        }

        fn admit(fixture: &Fixture, instance: usize, irp: u64, device: u64, memory: &Packet)
            -> Result<CallDriverAdmission, CallDriverRefusal>
        {
            let target = fixture.target;
            let owner = fixture.device;
            admit_call_driver(
                &fixture.io, &fixture.ledger, instance, fixture.source, irp, device, memory,
                |device| (device == owner).then_some(target),
            )
        }

        #[test]
        fn admits_an_owned_irp_whose_next_location_names_a_foreign_domain_device() {
            let fixture = fixture();
            let memory = packet(fixture.allocation, DEVICE);
            let admission = admit(&fixture, SOURCE, PACKET, DEVICE, &memory).unwrap();
            assert_eq!(admission.allocation, fixture.allocation);
            assert_eq!(admission.target.device_id(), fixture.device);
            assert_eq!(admission.target_domain, fixture.target);
            assert_eq!(admission.major, 3);
        }

        #[test]
        fn refuses_an_irp_the_lane_instance_does_not_own() {
            let fixture = fixture();
            let memory = packet(fixture.allocation, DEVICE);
            assert_eq!(admit(&fixture, SOURCE + 1, PACKET, DEVICE, &memory).err(),
                Some(CallDriverRefusal::ForeignIrp), "another instance's packet");
            assert_eq!(admit(&fixture, SOURCE, PACKET + 0x400, DEVICE, &memory).err(),
                Some(CallDriverRefusal::ForeignIrp), "an unregistered packet");
            assert_eq!(CallDriverRefusal::ForeignIrp.status(), NtStatus::INVALID_HANDLE);
        }

        #[test]
        fn refuses_a_device_with_no_registration_in_the_source_domain() {
            let fixture = fixture();
            let memory = packet(fixture.allocation, DEVICE + 0x100);
            assert_eq!(admit(&fixture, SOURCE, PACKET, DEVICE + 0x100, &memory).err(),
                Some(CallDriverRefusal::ForeignDevice));
            assert_eq!(CallDriverRefusal::ForeignDevice.status(), NtStatus::INVALID_DEVICE_REQUEST);
        }

        #[test]
        fn refuses_a_next_stack_location_that_names_another_device() {
            let fixture = fixture();
            let memory = packet(fixture.allocation, DEVICE + 0x100);
            assert_eq!(admit(&fixture, SOURCE, PACKET, DEVICE, &memory).err(),
                Some(CallDriverRefusal::StackMismatch));
            let mut memory = packet(fixture.allocation, DEVICE);
            memory.irp.current_location = 1;
            assert_eq!(admit(&fixture, SOURCE, PACKET, DEVICE, &memory).err(),
                Some(CallDriverRefusal::StackMismatch), "no next stack location");
            assert_eq!(CallDriverRefusal::StackMismatch.status(), NtStatus::INVALID_PARAMETER);
        }

        #[test]
        fn refuses_a_target_owned_by_the_source_domain_or_by_no_domain() {
            let mut fixture = fixture();
            let memory = packet(fixture.allocation, DEVICE);
            fixture.target = fixture.source;
            assert_eq!(admit(&fixture, SOURCE, PACKET, DEVICE, &memory).err(),
                Some(CallDriverRefusal::LocalTarget), "a same-domain target runs locally");
            assert_eq!(
                admit_call_driver(&fixture.io, &fixture.ledger, SOURCE, fixture.source, PACKET,
                    DEVICE, &memory, |_| None).err(),
                Some(CallDriverRefusal::ForeignDevice), "a device no instance dispatches");
        }

        #[test]
        fn admits_a_caller_projection_until_its_retirement_begins() {
            let mut fixture = fixture();
            let projected = SourceIrpAllocation {
                owner: SourceIrpOwner::HostedCaller(SOURCE),
                component_address: PACKET + 0x400,
                ..fixture.allocation
            };
            let ticket = fixture.ledger.register(projected).unwrap();
            let memory = packet(projected, DEVICE);
            let admit_projected =
                |fixture: &Fixture| admit(fixture, SOURCE, PACKET + 0x400, DEVICE, &memory);
            assert_eq!(admit_projected(&fixture).map(|admission| admission.allocation),
                Ok(projected));
            fixture.ledger.begin_hosted_caller_retirement(ticket, projected).unwrap();
            assert_eq!(admit_projected(&fixture).err(), Some(CallDriverRefusal::ForeignIrp),
                "a retiring packet is no longer forwardable");
        }
    }
}
