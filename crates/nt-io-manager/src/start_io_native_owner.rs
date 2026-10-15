//! Exact native StartIo source/device admission and pending-node identity.
//!
//! The provider's pending node remains the packet owner. This value is an observation of its
//! generation and root-issued source ticket, not a second queue or a source allocation pin.
//! It may be held across callbacks only together with the canonical node owner's phase claim.
//! StartIoAdmission obtains real source and device owners before any future WDM queue effect.

use crate::retained_query_path_forward::SourceIrpTicket;
use crate::source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity, SourceIrpLedger,
    SourceIrpLedgerError};
use crate::{HostedDevicePointerRegistration, HostedDeviceProjectionReference,
    HostedDomainIdentity, IoManager};
use nt_status::NtStatus;

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
pub enum StartIoAdmissionError {
    Source(SourceIrpLedgerError),
    WrongSourceAllocation,
    WrongPendingNode,
    WrongDispatchDevice,
    Device(NtStatus),
    AlreadyRetained,
    NoCapacity,
}

/// One real source-ledger pin. The ticket and allocation are observations; this non-Copy value
/// carries the obligation to release the pin after exact terminal observation or refusal.
#[derive(Debug)]
#[must_use = "transfer or release the admitted source pin"]
pub struct StartIoSourcePin {
    identity: SourceIrpForwardIdentity,
    held: bool,
}

impl StartIoSourcePin {
    pub fn identity(&self) -> SourceIrpForwardIdentity { self.identity }

    pub fn release(&mut self, ledger: &mut SourceIrpLedger) -> Result<(), SourceIrpLedgerError> {
        if !self.held || !ledger.admits_forward(self.identity.ticket(), self.identity.allocation()) {
            return Err(SourceIrpLedgerError::WrongIdentity);
        }
        ledger.unpin(self.identity.ticket())?;
        self.held = false;
        Ok(())
    }
}

/// Atomic local acquisition of physical source and logical device projection owners. The source
/// domain deliberately need not equal the device projection domain. No WDM queue write occurs
/// here; the native adapter transfers these owners into its canonical queue/current receipt.
#[derive(Debug)]
#[must_use = "transfer both owners into the canonical queue/current receipt or release them"]
pub struct StartIoAdmission {
    source: StartIoSourcePin,
    registration: HostedDevicePointerRegistration,
    device: Option<HostedDeviceProjectionReference>,
}

impl StartIoAdmission {
    /// The native caller must first validate `registered` against the root op6 caller-projection
    /// row, `observed` against the live pending-node phase/generation, and
    /// `dispatch_device` against the authenticated canonical dispatch target. An op6 row does
    /// not carry device authority. This binds both independent witnesses to real source and
    /// device owners before any WDM queue write.
    pub fn acquire_projected<P>(
        io: &mut IoManager<P>,
        ledger: &mut SourceIrpLedger,
        expected_source: SourceIrpAllocation,
        registered: PendingStartIoQueueIdentity,
        observed: PendingStartIoNodeIdentity,
        dispatch_device: HostedDevicePointerRegistration,
    ) -> Result<Self, StartIoAdmissionError> {
        if registered.device != dispatch_device {
            return Err(StartIoAdmissionError::WrongDispatchDevice);
        }
        if !matches!(expected_source.owner, crate::source_irp_ledger::SourceIrpOwner::HostedCaller(_))
            || !registered.packet.matches(observed)
            || observed.raw_irp != expected_source.component_address
            || observed.source.domain != expected_source.domain
        {
            return Err(StartIoAdmissionError::WrongPendingNode);
        }
        let Some((ticket, allocation)) = ledger.registered(
            expected_source.owner, expected_source.domain, expected_source.component_address,
        ) else {
            return Err(StartIoAdmissionError::Source(SourceIrpLedgerError::NotFound));
        };
        if allocation != expected_source {
            return Err(StartIoAdmissionError::WrongSourceAllocation);
        }
        if ticket != observed.source {
            return Err(StartIoAdmissionError::WrongPendingNode);
        }
        // The caller holds the source lock through admission; this second exact check prevents
        // a borrowed ticket observation from serving as the physical lifetime owner.
        Self::acquire(io, ledger, expected_source, registered.device)
    }

    pub fn acquire<P>(
        io: &mut IoManager<P>,
        ledger: &mut SourceIrpLedger,
        expected_source: SourceIrpAllocation,
        device: HostedDevicePointerRegistration,
    ) -> Result<Self, StartIoAdmissionError> {
        let (ticket, allocation) = ledger.pin(
            expected_source.owner,
            expected_source.domain,
            expected_source.component_address,
        ).map_err(StartIoAdmissionError::Source)?;
        if allocation != expected_source {
            ledger.unpin(ticket).expect("new StartIo pin changed before local rollback");
            return Err(StartIoAdmissionError::WrongSourceAllocation);
        }
        let identity = SourceIrpForwardIdentity::new(ticket, allocation)
            .expect("source ledger returned an invalid registered allocation");
        let projection = match io.retain_hosted_device_projection_reference(device) {
            Ok(projection) => projection,
            Err(status) => {
                ledger.unpin(ticket).expect("new StartIo pin changed before local rollback");
                return Err(StartIoAdmissionError::Device(status));
            }
        };
        Ok(Self { source: StartIoSourcePin { identity, held: true }, registration: device,
            device: Some(projection) })
    }

    pub fn into_owners(self) -> (HostedDeviceProjectionReference, StartIoSourcePin) {
        (self.device.expect("admitted StartIo device owner"), self.source)
    }

    pub fn source_identity(&self) -> SourceIrpForwardIdentity { self.source.identity() }

    pub fn device_registration(&self) -> HostedDevicePointerRegistration {
        self.registration
    }

    /// Called after a proved no-effect queue refusal or exact terminal withdrawal. Keep the
    /// physical source pinned if device release refuses, so storage cannot retire prematurely.
    pub fn release<P>(&mut self, io: &mut IoManager<P>, ledger: &mut SourceIrpLedger)
        -> Result<(), StartIoAdmissionError>
    {
        if let Some(device) = self.device.as_mut() {
            device.release(io).map_err(StartIoAdmissionError::Device)?;
            self.device = None;
        }
        if self.source.held {
            self.source.release(ledger).map_err(StartIoAdmissionError::Source)?;
        }
        Ok(())
    }
}

impl SourceIrpLedger {
    /// Retain the owner transaction before provider queue effects. This is an ownership ledger,
    /// not an alternative packet queue: selection remains in the WDM KDEVICE_QUEUE.
    pub fn retain_start_io<P>(
        &mut self, io: &mut IoManager<P>, expected_source: SourceIrpAllocation,
        device: HostedDevicePointerRegistration,
    ) -> Result<SourceIrpTicket, StartIoAdmissionError> {
        if self.start_io_owners.iter().any(|owner| {
            owner.source_identity().allocation() == expected_source
        }) {
            return Err(StartIoAdmissionError::AlreadyRetained);
        }
        self.start_io_owners.try_reserve(1).map_err(|_| StartIoAdmissionError::NoCapacity)?;
        let admission = StartIoAdmission::acquire(io, self, expected_source, device)?;
        let ticket = admission.source_identity().ticket();
        self.start_io_owners.push(admission);
        Ok(ticket)
    }

    pub fn start_io_registration(&self, ticket: SourceIrpTicket)
        -> Option<HostedDevicePointerRegistration>
    {
        self.start_io_owners.iter()
            .find(|owner| owner.source_identity().ticket() == ticket)
            .map(StartIoAdmission::device_registration)
    }

    pub fn start_io_allocation(&self, ticket: SourceIrpTicket,
        device: HostedDevicePointerRegistration) -> Option<SourceIrpAllocation>
    {
        self.start_io_owners.iter()
            .find(|owner| owner.source_identity().ticket() == ticket
                && owner.device_registration() == device)
            .map(|owner| owner.source_identity().allocation())
    }

    /// Transfer an exact owner to a locked native queue/current adapter. The caller must retain
    /// this non-Copy value across all foreign effects and any uncertain response.
    pub fn take_start_io(&mut self, ticket: SourceIrpTicket,
        device: HostedDevicePointerRegistration) -> Option<StartIoAdmission>
    {
        let index = self.start_io_owners.iter().position(|owner|
            owner.source_identity().ticket() == ticket && owner.device_registration() == device)?;
        Some(self.start_io_owners.swap_remove(index))
    }

    pub fn return_start_io(&mut self, admission: StartIoAdmission)
        -> Result<(), (StartIoAdmissionError, StartIoAdmission)>
    {
        if self.start_io_owners.iter().any(|owner|
            owner.source_identity().ticket() == admission.source_identity().ticket()) {
            return Err((StartIoAdmissionError::AlreadyRetained, admission));
        }
        if self.start_io_owners.try_reserve(1).is_err() {
            return Err((StartIoAdmissionError::NoCapacity, admission));
        }
        self.start_io_owners.push(admission);
        Ok(())
    }
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

/// Pairs a pending-node observation with a DEVICE_OBJECT registration. The op6 row authenticates
/// only the IRP: native admission must compare this registration with the independently
/// authenticated canonical dispatch device and retain the matching projection reference.
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
    use crate::source_irp_ledger::SourceIrpOwner;
    use crate::{DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType, DriverBackendId,
        DriverRecord, HostedDomainId, HostedDomainIdentity, MajorFunctionTable, MockObjectPort};
    use nt_types::{NtPath, ObjectId};

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

    #[test]
    fn admission_retains_exact_physical_source_and_logical_device_until_transfer() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str("\\Driver\\StartIoOwner").unwrap(),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ));
        let device = io.add_device(DeviceRecord::new(
            ObjectId::NULL, driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::empty(), 0,
        ));
        let physical = io.register_hosted_domain();
        let logical = io.register_hosted_domain();
        let registration = io.bind_hosted_device_pointer(logical, 0x4000, device).unwrap();
        let source = SourceIrpAllocation {
            owner: SourceIrpOwner::HostedDriver(3), domain: physical,
            component_address: 0x2000, bytes: 0x128, stack_count: 2, pool_generation: 7,
        };
        let mut ledger = SourceIrpLedger::new();
        let ticket = ledger.register(source).unwrap();
        let baseline = io.device_reference_count(device);
        let stale = SourceIrpAllocation { pool_generation: source.pool_generation + 1, ..source };
        assert!(matches!(StartIoAdmission::acquire(&mut io, &mut ledger, stale, registration),
            Err(StartIoAdmissionError::WrongSourceAllocation)));
        assert_eq!(ledger.unpin(ticket), Err(SourceIrpLedgerError::WrongIdentity));
        assert_eq!(io.device_reference_count(device), baseline);
        assert_eq!(ledger.retain_start_io(&mut io, source, registration), Ok(ticket));
        assert_eq!(ledger.start_io_registration(ticket), Some(registration));
        assert_eq!(ledger.retain_start_io(&mut io, source, registration),
            Err(StartIoAdmissionError::AlreadyRetained));
        assert_eq!(io.device_reference_count(device), baseline + 1);
        assert_eq!(io.retire_hosted_device_pointer(registration), Err(NtStatus::DEVICE_BUSY));
        assert_eq!(ledger.prepare_driver_free(3, physical, source.component_address),
            Err(SourceIrpLedgerError::Pinned));
        let other_device = io.add_device(DeviceRecord::new(
            ObjectId::NULL, driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::empty(), 0,
        ));
        let wrong_device = io.bind_hosted_device_pointer(logical, 0x5000, other_device).unwrap();
        assert!(ledger.take_start_io(ticket, wrong_device).is_none());
        let admission = ledger.take_start_io(ticket, registration).unwrap();
        assert_eq!(admission.source_identity().ticket(), ticket);
        assert_eq!(admission.source_identity().allocation(), source);
        ledger.return_start_io(admission).unwrap();
        let mut admission = ledger.take_start_io(ticket, registration).unwrap();
        admission.release(&mut io, &mut ledger).unwrap();
        io.retire_hosted_device_pointer(wrong_device).unwrap();
        assert_eq!(io.device_reference_count(device), baseline);
    }

    #[test]
    fn admission_refusal_rolls_back_new_pin_and_keeps_unrelated_device_owner() {
        let mut io = IoManager::new(MockObjectPort::new());
        let physical = io.register_hosted_domain();
        let source = SourceIrpAllocation {
            owner: SourceIrpOwner::HostedDriver(3), domain: physical,
            component_address: 0x2000, bytes: 0x128, stack_count: 2, pool_generation: 7,
        };
        let mut ledger = SourceIrpLedger::new();
        let ticket = ledger.register(source).unwrap();
        // A registration from another manager is rejected after source pinning.
        let mut other = IoManager::new(MockObjectPort::new());
        let driver = other.register_driver(DriverRecord::new(
            ObjectId::NULL, NtPath::parse_str("\\Driver\\ForeignStartIo").unwrap(),
            DriverBackendId(1), MajorFunctionTable::new(),
        ));
        let device = other.add_device(DeviceRecord::new(
            ObjectId::NULL, driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::empty(), 0,
        ));
        let foreign_domain = other.register_hosted_domain();
        let foreign = other.bind_hosted_device_pointer(foreign_domain, 0x4000, device).unwrap();
        assert!(matches!(StartIoAdmission::acquire(&mut io, &mut ledger, source, foreign),
            Err(StartIoAdmissionError::Device(_))));
        assert_eq!(ledger.unpin(ticket), Err(SourceIrpLedgerError::WrongIdentity),
            "refusal must have rolled back its sole source pin");
    }

    #[test]
    fn projected_packet_requires_exact_op6_ticket_node_and_device_before_queue_effect() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL, NtPath::parse_str("\\Driver\\ProjectedStartIo").unwrap(),
            DriverBackendId(1), MajorFunctionTable::new(),
        ));
        let device = io.add_device(DeviceRecord::new(
            ObjectId::NULL, driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::empty(), 0,
        ));
        let source_domain = io.register_hosted_domain();
        let projection_domain = io.register_hosted_domain();
        let registration = io.bind_hosted_device_pointer(projection_domain, 0x4000, device).unwrap();
        let source = SourceIrpAllocation {
            owner: SourceIrpOwner::HostedCaller(3), domain: source_domain,
            component_address: 0x2000, bytes: 0x128, stack_count: 2, pool_generation: 7,
        };
        let mut ledger = SourceIrpLedger::new();
        let ticket = ledger.register(source).unwrap();
        let registered = PendingStartIoNodeIdentity::new(0x1000, 0x100, 31, 0x2000, ticket).unwrap();
        let queue = PendingStartIoQueueIdentity::new(registered, registration).unwrap();
        let baseline = io.device_reference_count(device);

        let stale_node = PendingStartIoNodeIdentity::new(0x1000, 0x200, 31, 0x2000, ticket).unwrap();
        assert!(matches!(StartIoAdmission::acquire_projected(
            &mut io, &mut ledger, source, queue, stale_node, registration,
        ), Err(StartIoAdmissionError::WrongPendingNode)));
        let stale_ticket = SourceIrpTicket::new(source_domain, ticket.id.get(), ticket.generation.get() + 1).unwrap();
        let stale_source = PendingStartIoNodeIdentity::new(0x1000, 0x100, 31, 0x2000, stale_ticket).unwrap();
        assert!(matches!(StartIoAdmission::acquire_projected(
            &mut io, &mut ledger, source, queue, stale_source, registration,
        ), Err(StartIoAdmissionError::WrongPendingNode)));
        let reused_pool = SourceIrpAllocation { pool_generation: 8, ..source };
        assert!(matches!(StartIoAdmission::acquire_projected(
            &mut io, &mut ledger, reused_pool, queue, registered, registration,
        ), Err(StartIoAdmissionError::WrongSourceAllocation)));
        let other_device = io.add_device(DeviceRecord::new(
            ObjectId::NULL, driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::empty(), 0,
        ));
        let wrong_live = io.bind_hosted_device_pointer(projection_domain, 0x5000, other_device).unwrap();
        assert!(matches!(StartIoAdmission::acquire_projected(
            &mut io, &mut ledger, source, queue, registered, wrong_live,
        ), Err(StartIoAdmissionError::WrongDispatchDevice)));
        assert_eq!(io.retire_hosted_device_pointer(wrong_live), Ok(()));
        assert_eq!(io.device_reference_count(device), baseline);
        assert_eq!(ledger.unpin(ticket), Err(SourceIrpLedgerError::WrongIdentity));

        let mut admitted = StartIoAdmission::acquire_projected(
            &mut io, &mut ledger, source, queue, registered, registration,
        ).unwrap();
        assert_eq!(admitted.source_identity().ticket(), ticket);
        assert_eq!(admitted.source_identity().allocation(), source);
        assert_eq!(admitted.device_registration(), registration);
        assert_eq!(io.retire_hosted_device_pointer(registration), Err(NtStatus::DEVICE_BUSY));
        assert_eq!(ledger.begin_hosted_caller_retirement(ticket, source),
            Err(SourceIrpLedgerError::Pinned));
        admitted.release(&mut io, &mut ledger).unwrap();
        assert_eq!(io.device_reference_count(device), baseline);
    }
}
